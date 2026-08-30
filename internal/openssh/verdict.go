package openssh

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// Judge fills in the verdict and the note of every setting tui-ssh has an
// opinion about, and leaves the rest alone.
//
// The opinions are deliberately few and each one is a sentence a reader can
// argue with. A tool that painted half of sshd_config red would be ignored
// within a week; what earns attention is a short list of settings that really
// do decide whether a stranger can guess their way in.
func Judge(settings []ssh.Setting) []ssh.Setting {
	out := make([]ssh.Setting, len(settings))
	copy(out, settings)
	for i := range out {
		out[i].Verdict, out[i].Note = verdictFor(out[i].Key, out[i].Value)
	}
	return out
}

// verdictFor is the judgement table itself.
func verdictFor(key, value string) (ssh.Verdict, string) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch canonicalKey(key) {
	case "PermitRootLogin":
		switch normalized {
		case "no":
			return ssh.VerdictOK, ""
		case "prohibit-password", "without-password", "forced-commands-only":
			return ssh.VerdictWarn,
				"root can still log in, by key only. `no` keeps root out entirely."
		case "yes":
			return ssh.VerdictRisk,
				"root can log in directly, with a password. Every attacker knows " +
					"the account name."
		}
	case "PasswordAuthentication":
		if normalized == "no" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictRisk,
			"every account with a password is something a stranger can guess at."

	case "PubkeyAuthentication":
		if normalized == "yes" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictWarn,
			"with keys off, a password is the only way in."

	case KbdInteractiveKey, ChallengeResponseKey:
		if normalized == "no" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictWarn,
			"PAM's interactive prompt usually asks for the password, so passwords " +
				"can still work with PasswordAuthentication no."

	case "PermitEmptyPasswords":
		if normalized == "no" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictRisk,
			"an account with an empty password can log in."

	case "MaxAuthTries":
		tries, err := strconv.Atoi(normalized)
		switch {
		case err != nil:
			return ssh.VerdictNone, ""
		case tries <= 3:
			return ssh.VerdictOK, ""
		case tries <= 6:
			return ssh.VerdictWarn,
				"attempts per connection. 3 costs a legitimate user nothing."
		default:
			return ssh.VerdictRisk,
				fmt.Sprintf("%d guesses per connection, and a client can open "+
					"as many connections as it likes.", tries)
		}

	case "LoginGraceTime":
		seconds, ok := durationSeconds(normalized)
		switch {
		case !ok:
			return ssh.VerdictNone, ""
		case seconds == 0:
			return ssh.VerdictRisk,
				"0 lets an unauthenticated connection sit open forever."
		case seconds <= 60:
			return ssh.VerdictOK, ""
		default:
			return ssh.VerdictWarn,
				"an unauthenticated connection holds a slot this long."
		}

	case "Port":
		if normalized == strconv.Itoa(ssh.DefaultPort) || normalized == "" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictOK,
			"not the default port. The firewall has to allow it and every client " +
				"has to know it; it is not by itself a defence."

	case "ListenAddress":
		if loopbackOnly(value) {
			return ssh.VerdictOK,
				"reachable only from this machine, over the loopback."
		}
		return ssh.VerdictNone, ""

	case "AllowUsers", "AllowGroups":
		if normalized == "" {
			return ssh.VerdictNone, ""
		}
		return ssh.VerdictOK, "only these may log in; everyone else is refused."

	case "UsePAM":
		if normalized == "yes" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictWarn,
			"the account and session stack does not run, so a locked account may " +
				"still be able to log in."

	case "X11Forwarding":
		if normalized == "no" {
			return ssh.VerdictOK, ""
		}
		return ssh.VerdictWarn,
			"a forwarded X display is a path from the client back into the session."

	case "AllowTcpForwarding":
		if normalized == "no" {
			return ssh.VerdictOK, "this host cannot be used as a tunnel."
		}
		return ssh.VerdictWarn,
			"anyone who can log in can tunnel to anything this host can reach."

	case "ClientAliveInterval":
		seconds, err := strconv.Atoi(normalized)
		switch {
		case err != nil:
			return ssh.VerdictNone, ""
		case seconds == 0:
			return ssh.VerdictWarn,
				"with no keepalive, a session whose client vanished stays until " +
					"the kernel gives up on the socket."
		default:
			return ssh.VerdictOK, ""
		}

	case "Ciphers", "KexAlgorithms", "MACs":
		if weak := weakAlgorithms(canonicalKey(key), value); len(weak) > 0 {
			return ssh.VerdictRisk, "offers " + strings.Join(weak, ", ")
		}
		return ssh.VerdictOK, ""
	}
	return ssh.VerdictNone, ""
}

// durationSeconds reads LoginGraceTime, which is a plain number of seconds or
// a number with a unit.
func durationSeconds(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	unit := 1
	switch value[len(value)-1] {
	case 's':
		value = value[:len(value)-1]
	case 'm':
		unit, value = 60, value[:len(value)-1]
	case 'h':
		unit, value = 3600, value[:len(value)-1]
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return number * unit, true
}

// loopbackOnly reports whether every listen address is on the loopback.
func loopbackOnly(value string) bool {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		host := strings.Trim(field, "[]")
		if index := strings.LastIndexByte(host, ':'); index > 0 &&
			!strings.Contains(host[:index], ":") {
			host = host[:index]
		}
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			return false
		}
	}
	return true
}

// weakSubstrings are the fragments that mark an algorithm nobody should still
// be offering. They are matched as substrings because every one of them names
// a family: `-cbc` covers aes128-cbc through aes256-cbc, and `hmac-md5` covers
// the etm variant too.
//
// The lists are per keyword because the same fragment means different things:
// `sha1` in a MAC is a weak integrity check, while `sha1` in a key exchange is
// a broken one.
var weakSubstrings = map[string][]string{
	"Ciphers": {
		"-cbc", "3des", "arcfour", "blowfish", "cast128", "rijndael", "none",
	},
	"KexAlgorithms": {
		"group1-sha1", "group14-sha1", "group-exchange-sha1", "gss-group1-sha1",
	},
	"MACs": {
		"hmac-md5", "hmac-sha1", "umac-64", "ripemd160", "none",
	},
}

// weakAlgorithms returns the entries of an algorithm list that are weak,
// sorted so the note reads the same on every run.
//
// A list that starts with `+`, `-` or `^` modifies the built-in default rather
// than replacing it. Only a `+` can add something weak back, so that is the
// one form still worth checking; the others are left alone.
func weakAlgorithms(key, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	switch value[0] {
	case '-', '^':
		return nil
	case '+':
		value = value[1:]
	}

	var weak []string
	seen := map[string]bool{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || seen[entry] {
			continue
		}
		for _, fragment := range weakSubstrings[key] {
			if strings.Contains(entry, fragment) {
				seen[entry] = true
				weak = append(weak, entry)
				break
			}
		}
	}
	sort.Strings(weak)
	return weak
}

// JudgeHostKeys fills in the verdict of each host key. The judgement is about
// the algorithm and the size, which is all a public key tells you.
func JudgeHostKeys(keys []ssh.HostKey) []ssh.HostKey {
	out := make([]ssh.HostKey, len(keys))
	copy(out, keys)
	for i := range out {
		out[i].Verdict, out[i].Note = hostKeyVerdict(out[i])
	}
	return out
}

// hostKeyVerdict judges one host key.
func hostKeyVerdict(key ssh.HostKey) (ssh.Verdict, string) {
	switch strings.ToUpper(key.Type) {
	case "DSA":
		return ssh.VerdictRisk,
			"DSA host keys are 1024 bits by definition, and OpenSSH stopped " +
				"compiling support for them."
	case "RSA":
		switch {
		case key.Bits < 2048:
			return ssh.VerdictRisk,
				fmt.Sprintf("%d bits is below anything currently considered safe.",
					key.Bits)
		case key.Bits < 3072:
			return ssh.VerdictWarn,
				fmt.Sprintf("%d bits; ssh-keygen -A generates 3072 today.", key.Bits)
		}
		return ssh.VerdictOK, ""
	case "ED25519":
		return ssh.VerdictOK, ""
	}
	return ssh.VerdictNone, ""
}
