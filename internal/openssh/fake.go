package openssh

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The sample machine's configuration files. The main file puts its `Include`
// at the top, the way Fedora, Ubuntu and Arch all ship it today, which is what
// makes a drop-in able to win a keyword at all.
const (
	demoConfig = `# This is the sshd server system-wide configuration file.
# See sshd_config(5) for more information.

Include /etc/ssh/sshd_config.d/*.conf

Port 22
ListenAddress 0.0.0.0
PermitRootLogin prohibit-password
MaxAuthTries 6
LoginGraceTime 120
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PermitEmptyPasswords no
UsePAM yes
X11Forwarding yes
AllowTcpForwarding yes
ClientAliveInterval 0
Subsystem sftp /usr/libexec/openssh/sftp-server
`

	demoDistroDropInPath = DropInDir + "/50-distribution.conf"

	demoDistroDropIn = `# Shipped by the distribution.

SyslogFacility AUTHPRIV
GSSAPIAuthentication yes
`
)

// demoEffective is what `sshd -T` prints on the sample machine: every keyword
// with its value resolved, lower-cased, the way sshd itself writes it.
const demoEffective = `port 22
addressfamily any
listenaddress 0.0.0.0:22
usepam yes
logingracetime 120
permitrootlogin prohibit-password
maxauthtries 6
maxsessions 10
pubkeyauthentication yes
passwordauthentication yes
kbdinteractiveauthentication yes
permitemptypasswords no
gssapiauthentication yes
x11forwarding yes
allowtcpforwarding yes
clientaliveinterval 0
clientalivecountmax 3
syslogfacility AUTHPRIV
loglevel INFO
printmotd no
compression no
permittunnel no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr
kexalgorithms curve25519-sha256,ecdh-sha2-nistp256
macs hmac-sha2-256-etm@openssh.com,hmac-sha1
subsystem sftp /usr/libexec/openssh/sftp-server
`

// demoStamp names the host key backup directory in --demo. It is fixed so the
// preview a reader sees in the README is the preview the tool produces.
const demoStamp = "20260829-114500"

// Fake is an in-memory OpenSSH server. It backs --demo and the tests: every key
// works, every command is built and previewed exactly as the real backend
// builds it, and nothing reaches the system.
//
// The commands are recorded rather than run, and a hook applies to the
// in-memory model the change the real command would have made — so ending a
// session in --demo really does remove it from the list, and the argv the
// confirm dialog displayed is the argv a test can assert on.
type Fake struct {
	model ssh.Model
	run   *runner.Fake
	// staged is the pending file content, keyed by destination path. --demo
	// writes no file at all, so the "staging directory" is this map.
	staged map[string]string
}

// NewFake builds the sample machine: a stock server that still takes passwords
// and still lets root in, two people logged in, a week of somebody knocking,
// and three host keys, one of which is smaller than it should be.
func NewFake() *Fake {
	f := &Fake{staged: map[string]string{}}
	f.run = &runner.Fake{Prefix: "sudo -n", Hook: f.apply}
	f.reset()
	return f
}

// reset builds the sample state. It is a function rather than a literal so
// --demo starts from the same machine every time, however it was left.
func (f *Fake) reset() {
	files := map[string]string{
		ConfigPath:           demoConfig,
		demoDistroDropInPath: demoDistroDropIn,
	}
	f.model = ssh.Model{
		Backend:   "openssh",
		Effective: true,
		Files:     demoFiles(files),
		Service: ssh.Service{
			Unit: "sshd", Active: true, Enabled: true,
			ActiveState: "active", UnitFileState: "enabled",
			Since: "Thu 2026-08-27 09:14:02 UTC",
			Listeners: []ssh.Listener{
				{Address: "0.0.0.0", Port: 22, Process: "sshd"},
				{Address: "[::]", Port: 22, Process: "sshd"},
			},
			Guards: []ssh.Guard{
				{Name: "fail2ban", Unit: "fail2ban.service", State: "inactive"},
			},
		},
		Sessions: []ssh.Session{
			{
				ID: "12", User: "deploy", RemoteIP: "203.0.113.42",
				RemotePort: 51422, LocalPort: 22, TTY: "pts/0",
				Since: "Sat 2026-08-29 08:41:19 UTC", State: "active", Leader: 4711,
			},
			{
				ID: "15", User: "ana", RemoteIP: "198.51.100.9",
				RemotePort: 40118, LocalPort: 22, TTY: "pts/1",
				Since: "Sat 2026-08-29 10:02:55 UTC", State: "active", Leader: 5218,
			},
		},
		HostKeys: JudgeHostKeys([]ssh.HostKey{
			{Path: HostKeyDir + "/ssh_host_ecdsa_key.pub", Type: "ECDSA", Bits: 256,
				Fingerprint: "SHA256:9Uf1YB0mAqxQnzTQ2pO0y1z8cH8h0m3nV5R2fLpKq0E",
				Comment:     "root@demo"},
			{Path: HostKeyDir + "/ssh_host_ed25519_key.pub", Type: "ED25519", Bits: 256,
				Fingerprint: "SHA256:QgousHKm5KgKimVkc5xRxiyguFe91dNy8yz18tS3IXQ",
				Comment:     "root@demo"},
			{Path: HostKeyDir + "/ssh_host_rsa_key.pub", Type: "RSA", Bits: 2048,
				Fingerprint: "SHA256:aM2oO7pT1xVb9kR4sE6uJ3wY5nC8dG0hQ2iL7fXzB1c",
				Comment:     "root@demo"},
		}),
		Firewall: FirewallUFW,
	}
	f.model.Settings = f.settings(demoEffective)
	f.model.Auth = ParseAuthLog(demoAuthLog(), ssh.Window24h,
		"journalctl -u sshd -u ssh --since -24h")
}

// demoFiles parses the sample machine's configuration the way the real backend
// parses the host's: through the same include walk, so --demo exercises the
// parser rather than a shortcut around it.
func demoFiles(files map[string]string) []ssh.ConfigFile {
	read := func(path string) (string, error) {
		raw, ok := files[path]
		if !ok {
			return "", fmt.Errorf("open %s: no such file or directory", path)
		}
		return raw, nil
	}
	glob := func(pattern string) ([]string, error) {
		var matches []string
		for path := range files {
			if ok, _ := filepath.Match(pattern, path); ok {
				matches = append(matches, path)
			}
		}
		return matches, nil
	}
	return ParseConfigTree(read, glob, ConfigPath)
}

// settings runs the effective output through the same pipeline the real
// backend runs it through: parse, attach the file evidence, judge, order.
func (f *Fake) settings(effective string) []ssh.Setting {
	return Order(Judge(AttachSources(ParseEffective(effective), f.model.Files)))
}

// demoAuthLog builds the sample machine's authentication log: three people
// getting in, and three addresses working through a user list. The counts the
// screen shows are counted from these lines rather than written down, so the
// demo and a real machine go through the same parser.
func demoAuthLog() string {
	var b strings.Builder
	write := func(stamp string, pid int, message string) {
		fmt.Fprintf(&b, "2026-08-29T%s demo sshd[%d]: %s\n", stamp, pid, message)
	}

	// The knocking: 37 failures across three addresses, each working through
	// its own short list of accounts.
	attackers := []struct {
		ip       string
		users    []string
		failures int
	}{
		{"203.0.113.7", []string{"root", "admin", "test"}, 21},
		{"198.51.100.23", []string{"oracle", "postgres"}, 11},
		{"192.0.2.66", []string{"ubuntu"}, 5},
	}
	minute, pid := 0, 20000
	for _, attacker := range attackers {
		for i := range attacker.failures {
			user := attacker.users[i%len(attacker.users)]
			pid++
			minute++
			stamp := fmt.Sprintf("%02d:%02d:%02d+0000", 2+minute/60, minute%60, i%60)
			port := 40000 + i
			if user != "root" {
				write(stamp, pid, fmt.Sprintf(
					"Invalid user %s from %s port %d", user, attacker.ip, port))
				write(stamp, pid, fmt.Sprintf(
					"Failed password for invalid user %s from %s port %d ssh2",
					user, attacker.ip, port))
				continue
			}
			write(stamp, pid, fmt.Sprintf(
				"Failed password for %s from %s port %d ssh2",
				user, attacker.ip, port))
		}
	}

	// And the people who actually work here.
	write("08:41:19+0000", 4711, "Accepted publickey for deploy from "+
		"203.0.113.42 port 51422 ssh2: ED25519 SHA256:t1Q9lqYb2xW")
	write("10:02:55+0000", 5218, "Accepted publickey for ana from "+
		"198.51.100.9 port 40118 ssh2: ED25519 SHA256:kR7pVn0dU3s")
	write("11:15:03+0000", 5901,
		"Accepted password for backup from 192.0.2.10 port 33210 ssh2")
	return b.String()
}

// Name identifies the backend. It is the real backend's name, because --demo
// shows what the real one would show.
func (f *Fake) Name() string { return "openssh" }

// Describe says plainly that nothing here is real.
func (f *Fake) Describe() string { return "demo (in-memory sample server)" }

// Capabilities reports the same capabilities as the real backend.
func (f *Fake) Capabilities() ssh.Capabilities { return capabilities }

// Preview renders the command line the real backend would run.
func (f *Fake) Preview(cmd ssh.Command) string { return f.run.Preview(cmd) }

// Load returns the sample machine.
func (f *Fake) Load(_ context.Context, window string) (ssh.Model, error) {
	model := f.model
	if window != ssh.Window24h {
		log, err := f.LoadAuth(context.Background(), model, window)
		if err != nil {
			return ssh.Model{}, err
		}
		model.Auth = log
	}
	return model, nil
}

// LoadAuth returns the sample log over a window. The sample machine has one
// day of history, so a week reports the same events and says so.
func (f *Fake) LoadAuth(_ context.Context, _ ssh.Model,
	window string) (ssh.AuthLog, error) {
	if _, err := sinceFor(window); err != nil {
		return ssh.AuthLog{}, err
	}
	log := ParseAuthLog(demoAuthLog(), window,
		"journalctl -u sshd -u ssh --since "+windowArgument(window))
	if window == ssh.Window7d {
		log.Unavailable = "the sample machine has one day of history, " +
			"so a week shows the same events"
	}
	return log, nil
}

// windowArgument is the `--since` value for a window, for the demo's own
// source line. It cannot fail here: the window was validated above.
func windowArgument(window string) string {
	since, _ := sinceFor(window)
	return since
}

// Run records the command and applies its effect to the sample machine.
func (f *Fake) Run(ctx context.Context, cmd ssh.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Ran exposes the recorded commands, which is what a test asserts on.
func (f *Fake) Ran() []ssh.Command { return f.run.Ran }

// apply is the hook the fake runner calls: it makes to the in-memory machine
// the change the real command would have made, so the demo stays coherent as
// keys are pressed.
func (f *Fake) apply(cmd ssh.Command) (string, error) {
	argv := cmd.Argv
	if len(argv) < 2 {
		return "", nil
	}
	switch {
	case argv[0] == "install" && argv[1] == "-m":
		return f.installDropIn(argv)
	case argv[0] == "loginctl" && argv[1] == "terminate-session":
		return f.terminate(argv[2])
	case argv[0] == "ssh-keygen" && argv[1] == "-A":
		return f.regenerateHostKeys()
	}
	return "", nil
}

// installDropIn applies the staged drop-in to the sample machine and
// recomputes what sshd would then report.
func (f *Fake) installDropIn(argv []string) (string, error) {
	destination := argv[len(argv)-1]
	content, ok := f.staged[destination]
	if !ok {
		return "", fmt.Errorf("install: nothing staged for %s", destination)
	}

	files := map[string]string{
		ConfigPath:           demoConfig,
		demoDistroDropInPath: demoDistroDropIn,
		destination:          content,
	}
	for _, file := range f.model.Files {
		if _, known := files[file.Path]; !known {
			files[file.Path] = file.Raw
		}
	}
	f.model.Files = demoFiles(files)
	f.model.Settings = f.settings(applyDropIn(demoEffective, content))
	return "", nil
}

// applyDropIn folds the drop-in's keywords into the effective output, which is
// what a real sshd would report after the reload.
//
// The sample machine's sshd_config carries its `Include` at the top, so the
// drop-in gets the first word on every keyword it sets — which is exactly the
// rule the editor's own warning is about, and the demo has to obey it too.
func applyDropIn(effective, dropIn string) string {
	values := map[string]string{}
	for _, setting := range parseDropIn(dropIn) {
		values[strings.ToLower(setting.key)] = setting.value
	}

	var b strings.Builder
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(effective, "\n"), "\n") {
		key, _, ok := splitDirective(line)
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		if value, override := values[key]; override {
			fmt.Fprintf(&b, "%s %s\n", key, value)
			seen[key] = true
			continue
		}
		b.WriteString(line + "\n")
	}
	// A keyword the sample sshd did not print at all is still in force once it
	// is written, so it is appended rather than dropped.
	for _, setting := range parseDropIn(dropIn) {
		if key := strings.ToLower(setting.key); !seen[key] {
			fmt.Fprintf(&b, "%s %s\n", key, setting.value)
		}
	}
	return b.String()
}

// terminate removes a session from the sample machine.
func (f *Fake) terminate(id string) (string, error) {
	for i, session := range f.model.Sessions {
		if session.ID != id {
			continue
		}
		f.model.Sessions = append(f.model.Sessions[:i:i],
			f.model.Sessions[i+1:]...)
		return "", nil
	}
	//nolint:staticcheck // ST1005: this is loginctl's own message, quoted
	return "", fmt.Errorf("Failed to terminate session: No session '%s' known", id)
}

// regenerateHostKeys gives the sample machine a fresh set, so the fingerprints
// on screen change the way they would on a real one.
func (f *Fake) regenerateHostKeys() (string, error) {
	fresh := []ssh.HostKey{
		{Path: HostKeyDir + "/ssh_host_ecdsa_key.pub", Type: "ECDSA", Bits: 256,
			Fingerprint: "SHA256:N3wEcDsAk3yF0rTh3D3m0M4ch1n3Xy1Z2aB3cD4", Comment: "root@demo"},
		{Path: HostKeyDir + "/ssh_host_ed25519_key.pub", Type: "ED25519", Bits: 256,
			Fingerprint: "SHA256:N3wEd25519k3yF0rTh3D3m0M4ch1n3Q7rS8tU9v", Comment: "root@demo"},
		{Path: HostKeyDir + "/ssh_host_rsa_key.pub", Type: "RSA", Bits: 3072,
			Fingerprint: "SHA256:N3wRs4k3yF0rTh3D3m0M4ch1n3W1x2Y3z4A5b6C", Comment: "root@demo"},
	}
	f.model.HostKeys = JudgeHostKeys(fresh)
	return "", nil
}

// BuildSetOption stages the drop-in in memory and returns the same plan the
// real backend returns — the same diff, and the same two commands. --demo
// writes nothing at all, so the staging path is a name rather than a file.
func (f *Fake) BuildSetOption(model ssh.Model, key, value string) (ssh.WritePlan, error) {
	key = WriteKeyFor(key, true)
	before := ""
	if file, ok := model.File(DropInPath); ok {
		before = file.Raw
	}
	content, err := RenderDropIn(before, key, value)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	if before == content {
		return ssh.WritePlan{}, fmt.Errorf("%s already says exactly this", DropInPath)
	}

	temp := "/tmp/tui-ssh/" + DropInName
	f.staged[DropInPath] = content
	validate, err := BuildValidate(temp)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	installCmd, err := BuildInstallDropIn(temp)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	reloadCmd, err := BuildReload(model.Service.Unit)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	return ssh.WritePlan{
		Path:     DropInPath,
		Content:  content,
		Diff:     Diff(DropInPath, before, content),
		TempPath: temp,
		Warning:  warningFor(model, key, value),
		// The sample machine has no sshd to ask, so the check is reported as
		// the real one reports a pass — the command line is the one the real
		// backend would run, and the value it approved is one RenderDropIn
		// already validated against the same rules.
		Validated:         true,
		Validation:        "accepted by " + f.Preview(validate),
		ValidationCommand: f.Preview(validate),
		Commands:          []ssh.Command{installCmd, reloadCmd},
	}, nil
}

// BuildReload asks the service to re-read its configuration.
func (f *Fake) BuildReload(model ssh.Model) (ssh.Command, error) {
	return BuildReload(model.Service.Unit)
}

// BuildTerminateSession ends one login.
func (f *Fake) BuildTerminateSession(session ssh.Session) (ssh.Command, error) {
	return BuildTerminateSession(session)
}

// BuildRegenerateHostKeys replaces the sample machine's host keys.
func (f *Fake) BuildRegenerateHostKeys(model ssh.Model) ([]ssh.Command, error) {
	return BuildRegenerateHostKeys(model.HostKeys, model.Service.Unit, demoStamp)
}

// BuildDenyIP blocks an address at the sample machine's firewall.
func (f *Fake) BuildDenyIP(model ssh.Model, ip string) (ssh.Command, error) {
	return BuildDenyIP(model.Firewall, ip)
}
