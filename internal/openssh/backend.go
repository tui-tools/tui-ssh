// Package openssh is the OpenSSH backend of tui-ssh, and the only place in the
// repository that starts a process.
//
// Everything about reaching the machine — resolving the binaries, applying the
// privilege prefix, bounding each call, turning a failure into one readable
// line — belongs to the kit runner. What is left here is the translation
// between OpenSSH's output and the backend-neutral model in internal/ssh, and
// the assembly of the argv that a confirm dialog will show before it runs.
//
// The programs driven, each through its own runner:
//
//	sshd         the effective configuration (`sshd -T`) and the syntax check
//	systemctl    the unit's state, and the reload that applies a change
//	ss           the sockets: who is connected, and what is being listened on
//	loginctl     the logins behind those sockets, and the one verb that ends one
//	journalctl   the authentication log
//	ssh-keygen   host key fingerprints, and the regeneration
//	install/mv   the two commands that put a file where it belongs
//	ufw          blocking an address, and only when ufw is the active firewall
//
// A ninth, `cat`, is the escalated fallback for a configuration file an
// unprivileged process cannot open — which on Fedora and Arch is sshd_config
// itself.
package openssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// ErrNotAvailable reports that the openssh backend cannot be used on this
// machine (sshd missing, or no non-interactive privilege escalation).
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the locations a non-root PATH commonly omits. sshd and ss
// live in an sbin directory on most distributions, which is exactly the case
// this exists for.
var searchPaths = map[string][]string{
	"sshd":       {"/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"},
	"systemctl":  {"/usr/bin/systemctl", "/bin/systemctl"},
	"ss":         {"/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss"},
	"loginctl":   {"/usr/bin/loginctl", "/bin/loginctl"},
	"journalctl": {"/usr/bin/journalctl", "/bin/journalctl"},
	"ssh-keygen": {"/usr/bin/ssh-keygen", "/bin/ssh-keygen"},
	"install":    {"/usr/bin/install", "/bin/install"},
	"mv":         {"/usr/bin/mv", "/bin/mv"},
	"cat":        {"/usr/bin/cat", "/bin/cat"},
	"ufw":        {"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"},
}

// installHint is appended to the "not found" error.
const installHint = "install the openssh-server package; " +
	"or use --demo to explore the UI"

// unitCandidates are the names the SSH server's unit goes by. Debian and
// Ubuntu call it `ssh` and ship `sshd.service` as an alias; Fedora, Arch and
// openSUSE call it `sshd`. Which one this machine uses is read, not assumed.
var unitCandidates = []string{"sshd", "ssh"}

// journalUnits are the units the authentication log is read from. Both names
// are passed because a machine can carry the alias, and journalctl is happy to
// be given a unit that has never logged anything.
var journalUnits = []string{"sshd", "ssh"}

// journalLines bounds how much of the log one read pulls back. A week of a
// machine under a scan is a lot of lines, and the screen shows counts and the
// most recent events rather than all of them.
const journalLines = "2000"

// authLogFallback is where the authentication log lives on a machine without a
// journal, which is a Debian or Ubuntu host running rsyslog.
const authLogFallback = "/var/log/auth.log"

// guardUnits are the brute-force blockers tui-ssh reports on. It only reports:
// their rules belong to the tool that owns them.
var guardUnits = []struct{ name, unit string }{
	{"fail2ban", "fail2ban.service"},
	{"sshguard", "sshguard.service"},
}

// Real drives OpenSSH on the host. It satisfies ssh.Backend.
type Real struct {
	sshd       *runner.Runner
	systemctl  *runner.Runner
	ss         *runner.Runner
	loginctl   *runner.Runner
	journalctl *runner.Runner
	keygen     *runner.Runner
	install    *runner.Runner
	move       *runner.Runner
	ufw        *runner.Runner
	// cat is the escalated fallback for reading a configuration file an
	// unprivileged process cannot open. See readConfigFile.
	cat *runner.Runner

	// caps gates what only exists on a new enough OpenSSH. It comes from the
	// manifest, so no version number is written into this file.
	caps compat.Caps
	// now names the host key backup directory. It is a field so a test and a
	// screenshot get the same name every time.
	now func() time.Time
}

// Available reports whether an SSH server is installed on this host.
func Available() bool {
	return runner.Available("sshd", searchPaths["sshd"]...)
}

// NewReal locates the binaries and, when not running as root, validates the
// configured privilege prefix. sudoPrefix comes from the configuration
// ("sudo -n"); pass nil to run the commands directly.
//
// Most reads are unprivileged: the unit state, the sockets, the sessions, the
// journal and the host key fingerprints all answer to any user. Two are not —
// `sshd -T` and reading sshd_config on a distribution that ships it mode
// 0600 — and both fall back to something weaker rather than demanding a
// password the rest of the screen does not need.
func NewReal(sudoPrefix []string, caps compat.Caps) (*Real, error) {
	real := &Real{caps: caps, now: time.Now}
	unprivileged := false
	for _, spec := range []struct {
		bin    string
		target **runner.Runner
		reads  *bool
	}{
		// `sshd -T` is the one read that genuinely needs root: it opens the
		// host keys on the way to printing the configuration.
		{"sshd", &real.sshd, nil},
		{"systemctl", &real.systemctl, &unprivileged},
		{"ss", &real.ss, &unprivileged},
		{"loginctl", &real.loginctl, &unprivileged},
		{"journalctl", &real.journalctl, &unprivileged},
		{"ssh-keygen", &real.keygen, &unprivileged},
		{"install", &real.install, nil},
		{"mv", &real.move, nil},
		{"ufw", &real.ufw, nil},
	} {
		r, err := runner.New(runner.Options{
			Bin:             spec.bin,
			SearchPaths:     searchPaths[spec.bin],
			SudoPrefix:      sudoPrefix,
			InstallHint:     installHint,
			PrivilegedReads: spec.reads,
		})
		if err != nil {
			// Only sshd is essential: without ufw there is no address to
			// block, without loginctl no session to end, and the screen says
			// so where the missing data would have been.
			if spec.bin == "sshd" {
				return nil, err
			}
			continue
		}
		*spec.target = r
	}

	// The escalated fallback for a configuration file the plain read cannot
	// open. It is not part of the loop above because a machine without `cat`
	// simply has no fallback, which is not worth failing New over.
	real.cat, _ = runner.New(runner.Options{
		Bin:         "cat",
		SearchPaths: searchPaths["cat"],
		SudoPrefix:  sudoPrefix,
	})
	return real, nil
}

// Name identifies the backend. It is the manifest's backend name, which is
// what the version probe is keyed on.
func (r *Real) Name() string { return "openssh" }

// Describe names the backend for the header.
func (r *Real) Describe() string { return r.sshd.Describe() }

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() ssh.Capabilities { return capabilities }

// Preview renders the exact command line Run will execute. Every command goes
// through the runner of its own binary, so the preview carries the privilege
// prefix that binary will really be called with.
func (r *Real) Preview(cmd ssh.Command) string {
	if run := r.runnerFor(cmd); run != nil {
		return run.Preview(cmd)
	}
	return cmd.String()
}

// runnerFor picks the runner that owns a command, by its argv[0].
func (r *Real) runnerFor(cmd ssh.Command) *runner.Runner {
	if len(cmd.Argv) == 0 {
		return nil
	}
	switch cmd.Argv[0] {
	case "sshd":
		return r.sshd
	case "systemctl":
		return r.systemctl
	case "ss":
		return r.ss
	case "loginctl":
		return r.loginctl
	case "journalctl":
		return r.journalctl
	case "ssh-keygen":
		return r.keygen
	case "install":
		return r.install
	case "mv":
		return r.move
	case "ufw":
		return r.ufw
	default:
		return nil
	}
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd ssh.Command) (string, error) {
	run := r.runnerFor(cmd)
	if run == nil {
		return "", fmt.Errorf("openssh: %q is not available on this machine",
			firstArg(cmd))
	}
	return run.Run(ctx, cmd)
}

// firstArg names the binary a command wanted, for an error message.
func firstArg(cmd ssh.Command) string {
	if len(cmd.Argv) == 0 {
		return "(empty command)"
	}
	return cmd.Argv[0]
}

// Load reads the server's state.
//
// The read is layered, and every layer is allowed to fail on its own: a machine
// where `sshd -T` cannot run still shows the configuration its files carry and
// says in the header that this is what the files say rather than what sshd
// concluded. Only a total failure to find any configuration at all is an error.
func (r *Real) Load(ctx context.Context, window string) (ssh.Model, error) {
	model := ssh.Model{Backend: r.Name()}

	model.Files = ParseConfigTree(r.readConfigFile(ctx), filepath.Glob, ConfigPath)
	settings, effective, reason := r.loadSettings(ctx)
	if len(settings) == 0 && len(model.Files) == 0 {
		return ssh.Model{}, fmt.Errorf(
			"openssh: neither `sshd -T` nor %s could be read: %s", ConfigPath, reason)
	}
	model.Effective, model.EffectiveReason = effective, reason
	model.Settings = Order(Judge(AttachSources(settings, model.Files)))

	model.Service = r.loadService(ctx)
	model.Sessions = r.loadSessions(ctx, model.Port())
	model.HostKeys = JudgeHostKeys(r.loadHostKeys(ctx))
	model.Firewall = r.detectFirewall(ctx)

	auth, err := r.LoadAuth(ctx, model, window)
	if err != nil {
		auth = ssh.AuthLog{Window: window, Unavailable: err.Error()}
	}
	model.Auth = auth
	return model, nil
}

// loadSettings asks sshd what its configuration actually is, and falls back to
// the files when it cannot answer.
//
// `sshd -T` is worth escalating for: it prints every keyword including the ones
// nobody wrote, with the defaults resolved and the Includes already merged,
// which is the difference between "what the file says" and "what the server
// does". When it fails — no sudo, or a configuration it refuses to parse — the
// files are read instead and the screen says which of the two it is showing.
func (r *Real) loadSettings(ctx context.Context) (settings []ssh.Setting,
	effective bool, reason string) {
	out, err := r.sshd.Read(ctx, "sshd", "-T")
	if err == nil {
		if parsed := ParseEffective(out); len(parsed) > 0 {
			return parsed, true, ""
		}
		return nil, false, "`sshd -T` printed nothing that parsed as a setting"
	}
	return SettingsFromFiles(r.filesFor(ctx)), false, runner.FirstLine(err.Error())
}

// filesFor re-reads the configuration tree. loadSettings needs it before Load
// has stored it, and re-reading a handful of small files costs nothing.
func (r *Real) filesFor(ctx context.Context) []ssh.ConfigFile {
	return ParseConfigTree(r.readConfigFile(ctx), filepath.Glob, ConfigPath)
}

// readConfigFile returns the read function the include walk uses: a plain read
// first, escalating only when the file exists and is not readable.
//
// The escalation matters more here than it looks. Fedora and Arch ship
// /etc/ssh/sshd_config mode 0600, so on those machines an unprivileged read of
// the one file that configures the server fails, and without the fallback the
// tool would show every setting as coming from nowhere.
func (r *Real) readConfigFile(ctx context.Context) ReadFunc {
	return func(path string) (string, error) {
		raw, err := os.ReadFile(path) //nolint:gosec // the path comes from sshd's own configuration tree
		if err == nil {
			return string(raw), nil
		}
		if !os.IsPermission(err) || r.cat == nil {
			return "", err
		}
		return r.cat.Read(ctx, "cat", "--", path)
	}
}

// loadService reads the unit's state, what it is listening on, and which
// brute-force blockers are installed.
func (r *Real) loadService(ctx context.Context) ssh.Service {
	service := ssh.Service{Unit: unitCandidates[0]}
	if r.systemctl == nil {
		return service
	}

	for _, unit := range unitCandidates {
		out, err := r.systemctl.Read(ctx, "systemctl", "show", unit,
			"--property=LoadState", "--property=ActiveState",
			"--property=UnitFileState", "--property=ActiveEnterTimestamp")
		if err != nil {
			continue
		}
		properties := ParseProperties(out)
		if properties["LoadState"] == "not-found" {
			continue
		}
		service.Unit = unit
		service.ActiveState = properties["ActiveState"]
		service.UnitFileState = properties["UnitFileState"]
		service.Since = properties["ActiveEnterTimestamp"]
		service.Active = service.ActiveState == "active"
		service.Enabled = service.UnitFileState == "enabled" ||
			service.UnitFileState == "enabled-runtime" ||
			service.UnitFileState == "alias"
		break
	}

	if r.ss != nil {
		if out, err := r.ss.Read(ctx, "ss", "-tlnpH"); err == nil {
			service.Listeners = ParseListeners(out)
		}
	}
	for _, guard := range guardUnits {
		out, err := r.systemctl.Read(ctx, "systemctl", "show", guard.unit,
			"--property=LoadState", "--property=ActiveState")
		if err != nil {
			continue
		}
		properties := ParseProperties(out)
		if properties["LoadState"] == "not-found" {
			continue
		}
		service.Guards = append(service.Guards, ssh.Guard{
			Name:   guard.name,
			Unit:   guard.unit,
			State:  properties["ActiveState"],
			Active: properties["ActiveState"] == "active",
		})
	}
	return service
}

// loadSessions reads the live logins: what logind knows about each one, joined
// to the socket the kernel has under it.
func (r *Real) loadSessions(ctx context.Context, port int) []ssh.Session {
	var logind []ssh.Session
	if r.loginctl != nil {
		if out, err := r.loginctl.Read(ctx, "loginctl", "list-sessions",
			"--no-legend", "--no-pager"); err == nil {
			for _, id := range ParseLoginctlSessions(out) {
				detail, readErr := r.loginctl.Read(ctx, "loginctl", "show-session", id)
				if readErr != nil {
					continue
				}
				if session, ok := ParseShowSession(detail); ok {
					logind = append(logind, session)
				}
			}
		}
	}

	var sockets []ssh.Session
	if r.ss != nil {
		// The filter is ss's own, in argv form: no shell is involved, so the
		// parentheses the manual page uses are not needed.
		out, err := r.ss.Read(ctx, "ss", "-tnpH", "state", "established",
			"sport", "=", fmt.Sprintf(":%d", port))
		if err == nil {
			sockets = ParseSSConnections(out)
		}
	}
	return MergeSessions(logind, sockets, port)
}

// LoadAuth reads the authentication log over one window.
func (r *Real) LoadAuth(ctx context.Context, model ssh.Model,
	window string) (ssh.AuthLog, error) {
	since, err := sinceFor(window)
	if err != nil {
		return ssh.AuthLog{}, err
	}

	if r.journalctl != nil {
		argv := []string{"journalctl"}
		for _, unit := range journalUnits {
			argv = append(argv, "-u", unit)
		}
		argv = append(argv, "--no-pager", "-o", "short-iso",
			"-n", journalLines, "--since", since)
		out, journalErr := r.journalctl.Read(ctx, argv...)
		if journalErr == nil {
			return ParseAuthLog(out, window,
				"journalctl -u "+strings.Join(journalUnits, " -u ")+
					" --since "+since), nil
		}
	}

	// No journal, or a journal that refused: a Debian or Ubuntu machine with
	// rsyslog has the same lines in a file. It is mode 0640 root:adm, so the
	// escalated read is what usually gets them.
	raw, err := r.readConfigFile(ctx)(authLogFallback)
	if err != nil {
		return ssh.AuthLog{}, fmt.Errorf(
			"no authentication log: neither the journal nor %s could be read",
			authLogFallback)
	}
	log := ParseAuthLog(raw, window, authLogFallback)
	log.Unavailable = "read from " + authLogFallback + ", which is not " +
		"filtered by time: the counts cover the whole file"
	return log, nil
}

// sinceFor turns a window into the `--since` argument journalctl takes.
func sinceFor(window string) (string, error) {
	switch window {
	case ssh.Window24h:
		return "-24h", nil
	case ssh.Window7d:
		return "-7d", nil
	default:
		return "", fmt.Errorf("openssh: %q is not a window this tool reads", window)
	}
}

// loadHostKeys reads the server's public host keys and their fingerprints.
//
// The directory is listed rather than derived from the configuration's HostKey
// lines, because a key file that exists but is not configured is worth seeing:
// `ssh-keygen -A` writes one for every type, and which of them sshd actually
// offers is a separate question the settings table answers.
func (r *Real) loadHostKeys(ctx context.Context) []ssh.HostKey {
	entries, err := os.ReadDir(HostKeyDir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "ssh_host_") ||
			!strings.HasSuffix(name, "_key.pub") {
			continue
		}
		paths = append(paths, filepath.Join(HostKeyDir, name))
	}
	sort.Strings(paths)

	var keys []ssh.HostKey
	for _, path := range paths {
		if r.keygen == nil {
			keys = append(keys, ssh.HostKey{Path: path})
			continue
		}
		out, keygenErr := r.keygen.Read(ctx, "ssh-keygen", "-l", "-f", path)
		if keygenErr != nil {
			continue
		}
		if key, ok := ParseFingerprint(path, out); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// detectFirewall reports which firewall is actually running, which is what
// decides whether blocking an address is an offer or a hint.
func (r *Real) detectFirewall(ctx context.Context) string {
	if r.ufw == nil || r.systemctl == nil {
		return ""
	}
	out, err := r.systemctl.Read(ctx, "systemctl", "show", "ufw.service",
		"--property=ActiveState")
	if err != nil {
		return ""
	}
	if ParseProperties(out)["ActiveState"] != "active" {
		return ""
	}
	return FirewallUFW
}

// BuildSetOption renders the drop-in that sets a keyword, checks it with the
// server's own parser and returns the plan that installs it.
//
// The check runs here, before the user is asked anything, and that is the whole
// point of it: a keyword sshd will not accept should be a message on the form,
// not a service that fails to reload after the file is already in /etc. It is a
// read — `sshd -t -f` parses a file and exits — so it is the one command in
// this package that runs without a confirmation, the same way the reads on the
// startup path do.
func (r *Real) BuildSetOption(model ssh.Model, key, value string) (ssh.WritePlan, error) {
	key = WriteKeyFor(key, r.caps.Has(FeatureKbdInteractive))
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

	temp, err := stageFile(DropInPath, content)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	plan := ssh.WritePlan{
		Path:     DropInPath,
		Content:  content,
		Diff:     Diff(DropInPath, before, content),
		TempPath: temp,
		Warning:  warningFor(model, key, value),
	}

	validate, err := BuildValidate(temp)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	plan.ValidationCommand = r.Preview(validate)
	out, err := r.Run(context.Background(), validate)
	switch {
	case err != nil && strings.TrimSpace(out) != "":
		return ssh.WritePlan{}, fmt.Errorf("sshd refused the file: %s",
			runner.FirstLine(out))
	case err != nil:
		// The check itself could not run — no sudo, most likely. That is not a
		// reason to refuse the edit, but it is a reason to say so on the dialog.
		plan.Validation = "could not run: " + runner.FirstLine(err.Error())
	default:
		plan.Validated = true
		plan.Validation = "accepted by " + plan.ValidationCommand
	}

	installCmd, err := BuildInstallDropIn(temp)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	reloadCmd, err := BuildReload(model.Service.Unit)
	if err != nil {
		return ssh.WritePlan{}, err
	}
	plan.Commands = []ssh.Command{installCmd, reloadCmd}
	return plan, nil
}

// warningFor is what the confirm dialog must say about this particular change
// beyond the diff: that the file being written would lose the keyword anyway,
// or that the way in is about to move.
//
// Both can be true at once, so they are collected rather than chosen between.
func warningFor(model ssh.Model, key, value string) string {
	var warnings []string

	// Does the file we are about to write actually decide this keyword? The
	// answer is read from the include order on this machine, not assumed from
	// what a distribution usually does.
	if _, ok := IncludeSite(model.Files); !ok {
		warnings = append(warnings, fmt.Sprintf(
			"Nothing in %s includes %s, so this file will not be read at all. "+
				"Add `Include %s/*.conf` at the top of %s first.",
			ConfigPath, DropInDir, DropInDir, ConfigPath))
	} else if winner, wins := WouldWin(model.Files, key); !wins {
		warnings = append(warnings, fmt.Sprintf(
			"%s is already set at %s, which sshd reads before this drop-in — "+
				"and it takes the FIRST value it is given, so what is written "+
				"here would be read and ignored. Change it there instead.",
			canonicalKey(key), winner))
	}

	switch canonicalKey(key) {
	case "Port", "ListenAddress":
		warnings = append(warnings,
			"This moves where the server accepts connections. The firewall has "+
				"to allow the new one before the reload, or the next login will "+
				"not get through — tui-firewall is the tool for that. Keep this "+
				"session open until you have tested a new one.")
	case "AllowUsers", "AllowGroups":
		warnings = append(warnings,
			"Setting this denies everyone not listed. Make sure your own "+
				"account is covered before you reload.")
	case "PubkeyAuthentication":
		if value == "no" {
			warnings = append(warnings,
				"With keys off, a password is the only way in — and if "+
					"PasswordAuthentication is also no, nothing is.")
		}
	}
	return strings.Join(warnings, "\n\n")
}

// stageFile writes the pending file to a private temporary directory and
// returns its path.
//
// Staging first is what makes the change reviewable and what makes the check
// meaningful: the file the user approves is a file that already exists and that
// sshd has already parsed, and `install` copies exactly that one. Nothing is
// written to /etc until the confirmed commands run.
func stageFile(destination, content string) (string, error) {
	dir, err := os.MkdirTemp("", "tui-ssh-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, filepath.Base(destination))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// BuildReload asks the service to re-read its configuration.
func (r *Real) BuildReload(model ssh.Model) (ssh.Command, error) {
	return BuildReload(model.Service.Unit)
}

// BuildTerminateSession ends one login.
func (r *Real) BuildTerminateSession(session ssh.Session) (ssh.Command, error) {
	return BuildTerminateSession(session)
}

// BuildRegenerateHostKeys moves the current host keys aside and generates a
// fresh set.
func (r *Real) BuildRegenerateHostKeys(model ssh.Model) ([]ssh.Command, error) {
	return BuildRegenerateHostKeys(model.HostKeys, model.Service.Unit,
		r.now().UTC().Format("20060102-150405"))
}

// BuildDenyIP blocks an address at the firewall.
func (r *Real) BuildDenyIP(model ssh.Model, ip string) (ssh.Command, error) {
	return BuildDenyIP(model.Firewall, ip)
}
