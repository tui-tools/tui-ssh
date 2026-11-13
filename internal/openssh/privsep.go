package openssh

import (
	"regexp"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// privsepRe matches the line sshd prints, and exits on, when the privilege
// separation directory compiled into it does not exist. It refuses `sshd -T`
// and `sshd -t -f` alike, before it reads a single keyword.
var privsepRe = regexp.MustCompile(`Missing privilege separation directory: (\S+)`)

// runtimePrivsepRe is the shape of a privilege separation directory that is a
// runtime directory: one level under /run (or /var/run, its compatibility
// link), which systemd creates when the service starts and removes when it
// stops. Debian and Ubuntu build sshd with /run/sshd. Other distributions use
// a directory the package ships (/var/empty/sshd, /usr/share/empty.sshd),
// whose absence is a broken installation and not something to create here.
var runtimePrivsepRe = regexp.MustCompile(`^/(?:var/)?run/[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// PrivsepDirMode is the mode systemd gives a RuntimeDirectory by default, and
// the mode sshd's own packaging creates /run/sshd with.
const PrivsepDirMode = "0755"

// MissingPrivsepDir reports whether sshd's output is the missing privilege
// separation directory message, and which directory it named. The directory is
// read from sshd's own words rather than assumed, because it is a build-time
// choice that differs between distributions.
func MissingPrivsepDir(out string) (string, bool) {
	match := privsepRe.FindStringSubmatch(out)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// IsRuntimePrivsepDir reports whether a privilege separation directory is a
// runtime directory, which is the only kind tui-ssh offers to create.
func IsRuntimePrivsepDir(dir string) bool {
	return runtimePrivsepRe.MatchString(dir)
}

// BuildEnsurePrivsepDir creates a missing runtime privilege separation
// directory the way systemd would: root-owned, mode 0755. It refuses anything
// that is not a single directory under /run, so a path sshd printed can never
// turn into a write somewhere else.
//
// When ssh.service starts later, systemd takes the directory over as its
// RuntimeDirectory and removes it when the service stops, which is fine.
func BuildEnsurePrivsepDir(dir string) (ssh.Command, error) {
	if !IsRuntimePrivsepDir(dir) {
		return ssh.Command{}, &ssh.PrivsepMissingError{Dir: dir,
			Explanation: dir + " is not a runtime directory under /run, so it is not created here"}
	}
	return ssh.Command{
		Argv: []string{"install", "-d", "-m", PrivsepDirMode,
			"-o", "root", "-g", "root", dir},
		Description: "Create " + dir + ", the directory sshd needs before it will check a file",
		Destructive: true,
	}, nil
}

// PrivsepExplanation is the sentence the header, --check and the editor show
// when sshd stops at the missing directory. It names the state the server is
// in, which on a socket-activated machine is simply "nothing has connected
// yet", and says how it ends.
func PrivsepExplanation(dir string, service ssh.Service) string {
	if !IsRuntimePrivsepDir(dir) {
		return "sshd's privilege separation directory " + dir + " is missing. " +
			"It ships with the OpenSSH server package rather than being created " +
			"at start, so reinstalling the package restores it; until then sshd " +
			"cannot check a configuration, and tui-ssh installs nothing unchecked"
	}
	unit := service.Unit
	if unit == "" {
		unit = "sshd"
	}
	if service.SocketActivated && !service.Active {
		return unit + ".service is idle under socket activation, and " + dir +
			" is its RuntimeDirectory: it appears when the service starts, on " +
			"the first connection or with `systemctl start " + unit + "`. Until " +
			"then sshd cannot check a configuration; an edit offers to create " + dir
	}
	return dir + " (the RuntimeDirectory of " + unit + ".service) does not exist, " +
		"so the service has not started since boot. Starting it creates the " +
		"directory; until then sshd cannot check a configuration, and an edit " +
		"offers to create " + dir
}

// privsepError is the error an edit returns when the check could not run for
// this reason: the explanation, and the fix when there is one to offer.
func privsepError(dir string, service ssh.Service) *ssh.PrivsepMissingError {
	failure := &ssh.PrivsepMissingError{Dir: dir,
		Explanation: PrivsepExplanation(dir, service)}
	if fix, err := BuildEnsurePrivsepDir(dir); err == nil {
		failure.Fix = &fix
	}
	return failure
}
