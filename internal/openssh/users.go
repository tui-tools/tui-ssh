package openssh

import (
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The two files the account list is read from.
const (
	// PasswdPath is the account database. It is world-readable on every
	// distribution, so this read never escalates.
	PasswdPath = "/etc/passwd"
	// GroupPath resolves a primary group id to the name `install -g` takes.
	GroupPath = "/etc/group"
)

// firstNormalUID is where a distribution's own accounts end and people begin.
// It is 1000 on every distribution this family runs on; root is added back by
// name, because root is the account whose keys matter most and its uid is 0.
const firstNormalUID = 1000

// maxNormalUID excludes the `nobody` account, which is uid 65534 and is not
// somebody who logs in.
const maxNormalUID = 60000

// nologinShells are the shells that mean "this account is not for logging in".
// A system account is not interesting to this screen and would bury the two or
// three accounts that are.
var nologinShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/usr/bin/nologin":  true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"":                  true,
}

// ParsePasswd reads /etc/passwd into the accounts somebody could log into over
// SSH: root, and the ordinary accounts with a real shell.
//
// The group id is resolved through groups, which ParseGroups builds from
// /etc/group. An account whose group is not in there keeps its own name, which
// is what every distribution's useradd creates.
func ParsePasswd(raw string, groups map[int]string) []ssh.User {
	var users []ssh.User
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 || strings.HasPrefix(line, "#") {
			continue
		}
		name, home, shell := fields[0], fields[5], fields[6]
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if !loginAccount(name, uid, shell) {
			continue
		}
		gid, _ := strconv.Atoi(fields[3])
		user := ssh.User{
			Name:     name,
			Group:    groups[gid],
			Home:     home,
			KeysPath: AuthorizedKeysPathFor(home),
		}
		if user.Group == "" {
			user.Group = name
		}
		if CheckUser(user) != nil {
			// An account this tool could not write a key for is not offered:
			// the picker only lists accounts whose plan can actually be built.
			continue
		}
		users = append(users, user)
	}
	sort.SliceStable(users, func(i, j int) bool {
		// root first, then alphabetically: root is the account a reader checks
		// first, and the rest are easier to find in a fixed order than in
		// /etc/passwd's own.
		if (users[i].Name == "root") != (users[j].Name == "root") {
			return users[i].Name == "root"
		}
		return users[i].Name < users[j].Name
	})
	return users
}

// loginAccount reports whether an account is one somebody logs into.
func loginAccount(name string, uid int, shell string) bool {
	if nologinShells[shell] {
		return false
	}
	if name == "root" {
		return true
	}
	return uid >= firstNormalUID && uid <= maxNormalUID
}

// ParseGroups reads /etc/group into the group name of each group id.
func ParseGroups(raw string) map[int]string {
	groups := map[int]string{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 3 {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if _, seen := groups[gid]; !seen {
			groups[gid] = fields[0]
		}
	}
	return groups
}

// LoadAuthorizedKeys fills in each account's keys, using a read function so the
// walk can be tested against fixtures and so the backend can supply the
// escalated read another account's home needs.
//
// A file that does not exist is not an error: it is an account nobody has given
// a key to, which is a normal and useful thing for the screen to say. A file
// that exists and cannot be read is reported as such, because "no keys" and
// "we were not allowed to look" are answers a reader must not confuse.
func LoadAuthorizedKeys(users []ssh.User, read ReadFunc) []ssh.User {
	out := make([]ssh.User, 0, len(users))
	for _, user := range users {
		raw, err := read(user.KeysPath)
		switch {
		case err != nil && isNotExist(err):
		case err != nil:
			user.Unreadable = err.Error()
		case len(raw) > maxAuthorizedKeysBytes:
			user.Unreadable = user.KeysPath + " is larger than this tool will rewrite"
		default:
			user.Keys = ParseAuthorizedKeys(raw)
		}
		out = append(out, user)
	}
	return out
}

// isNotExist reports that a read failed because the file is not there. The
// escalated fallback returns a `cat` message rather than an os error, so both
// forms are recognised.
func isNotExist(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such file or directory")
}
