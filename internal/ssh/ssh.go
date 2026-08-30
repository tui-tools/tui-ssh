// Package ssh defines the backend-agnostic model tui-ssh renders and the
// interface every SSH server implementation satisfies. The UI knows only these
// types: it never builds an sshd, systemctl, loginctl or journalctl argv
// itself. Mutations are Command values produced by the backend, shown in a
// preview dialog and only then executed.
package ssh

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// Command is a single privileged invocation the user is about to run. Argv
// excludes any privilege wrapper: the backend adds it when previewing and when
// executing.
//
// It is an alias rather than a type of its own, so a backend hands the very
// value the confirm dialog displayed straight to the kit runner, with no
// conversion in between. That identity is what makes the preview a promise.
type Command = runner.Command

// Verdict is what tui-ssh thinks of one setting's value. It is a string rather
// than an enum so `--check` reports a word a script can grep for.
type Verdict string

// The four verdicts. VerdictNone is the zero value and means "this setting is
// not one we judge" — most of sshd_config is like that, and pretending
// otherwise would bury the handful that matter.
const (
	VerdictNone Verdict = ""
	// VerdictOK is a value that closes the door it is about.
	VerdictOK Verdict = "ok"
	// VerdictWarn is a value that is defensible but worth seeing.
	VerdictWarn Verdict = "warn"
	// VerdictRisk is a value that opens the machine to something it does not
	// have to be open to.
	VerdictRisk Verdict = "risk"
)

// Source is one place a keyword is set: which file, which line, and the line
// as it is written there.
type Source struct {
	// File is the absolute path of the file carrying the line.
	File string
	// Line is the 1-based line number inside that file.
	Line int
	// Text is the line itself, whitespace trimmed.
	Text string
	// Match is the `Match` block the line sits inside, empty at file scope.
	// A keyword inside a Match block only applies to the connections that
	// block selects, which is why it is never treated as the winner.
	Match string
}

// String renders the source the way the settings table shows it.
func (s Source) String() string {
	if s.File == "" {
		return ""
	}
	if s.Line <= 0 {
		return s.File
	}
	return s.File + ":" + strconv.Itoa(s.Line)
}

// Setting is one sshd keyword with the value that is actually in force.
type Setting struct {
	// Key is the keyword in sshd's own spelling ("PermitRootLogin").
	Key string
	// Value is the value in force.
	Value string
	// Effective reports that Value came from `sshd -T`, which is sshd's own
	// answer, rather than from reading the files.
	Effective bool
	// Security marks a keyword from the security-relevant list, which is shown
	// first and is the only part of the file this tool has an opinion about.
	Security bool
	// Verdict and Note are that opinion. Note is one sentence, empty when
	// there is nothing worth adding — an ok verdict may still carry one when
	// the value is fine but has a consequence worth naming.
	Verdict Verdict
	Note    string
	// Sources are every place the keyword is written, in the order sshd reads
	// them. sshd takes the first value it is given for nearly every keyword,
	// so Sources[0] outside a Match block is the one that decides.
	Sources []Source
	// Default reports that no file sets this keyword: the value is sshd's own
	// compiled-in default.
	Default bool
}

// Winner is the source that decides this setting's value, and whether there is
// one. A keyword nobody wrote has no winner: the value is sshd's default.
func (s Setting) Winner() (Source, bool) {
	for _, source := range s.Sources {
		if source.Match == "" {
			return source, true
		}
	}
	return Source{}, false
}

// Shadowed reports that a file other than path already sets this keyword
// earlier in sshd's reading order, so a value written into path would never
// take effect. It is what the editor checks before offering to write.
func (s Setting) Shadowed(path string) bool {
	winner, ok := s.Winner()
	return ok && winner.File != path
}

// ConfigLine is one line of a configuration file, parsed.
type ConfigLine struct {
	// Number is the 1-based line number.
	Number int
	// Text is the line as written.
	Text string
	// Key and Value are the parsed keyword, empty on a comment or a blank line.
	Key   string
	Value string
	// Match is the Match block the line sits inside, empty at file scope.
	Match string
}

// ConfigFile is one sshd configuration file as it is on disk.
type ConfigFile struct {
	// Path is the absolute path of the file.
	Path string
	// Raw is the file's text, empty when it could not be read.
	Raw string
	// Unreadable explains why Raw is empty, when it is. On Fedora and Arch
	// /etc/ssh/sshd_config is mode 0600, so an unprivileged read of it fails
	// and the tool has to say so rather than show an empty file.
	Unreadable string
	// Lines are the parsed lines, in file order.
	Lines []ConfigLine
	// IncludedBy is the file whose `Include` pulled this one in, empty for the
	// top-level file, and IncludedAt is the line number of that `Include`.
	//
	// The pair is what lets the reading order be reconstructed. An `Include`
	// splices its files in at the line it appears on, so a file's contents are
	// not read after its parent's — they are read in the middle of it, and
	// which of two settings sshd sees first depends on that.
	IncludedBy string
	IncludedAt int
	// Order is the position of this file in the tree, used only to keep the
	// display stable.
	Order int
}

// Session is one live SSH login.
type Session struct {
	// ID is the logind session id, empty for a connection logind does not
	// know about (a session opened without PAM, or a machine without logind).
	ID string
	// User is the local account the session is for.
	User string
	// RemoteIP and RemotePort are the other end of the connection.
	RemoteIP   string
	RemotePort int
	// LocalPort is the port on this machine the connection landed on, which is
	// not always 22.
	LocalPort int
	// TTY is the terminal, empty for a session without one (sftp, a command).
	TTY string
	// Since is when the session started, as the source reported it.
	Since string
	// Leader is the session's leader process, 0 when unknown.
	Leader int
	// State is the logind session state ("active", "online", "closing").
	State string
}

// Label renders the session for a one-line summary.
func (s Session) Label() string {
	label := s.User + "@" + s.RemoteIP
	if s.ID != "" {
		label += " (session " + s.ID + ")"
	}
	return label
}

// Count is one row of a "top offenders" list.
type Count struct {
	Name  string
	Count int
}

// AuthEvent is one authentication line the log carried, classified.
type AuthEvent struct {
	// Kind is "accepted", "failed", "invalid-user" or "other".
	Kind string
	// User is the account the attempt was for, empty when the line names none.
	User string
	// IP is the source address, empty when the line names none.
	IP string
	// Method is the authentication method ("publickey", "password").
	Method string
	// Raw is the log line itself, which is what the detail view shows.
	Raw string
}

// The kinds an AuthEvent can carry.
const (
	AuthAccepted    = "accepted"
	AuthFailed      = "failed"
	AuthInvalidUser = "invalid-user"
	AuthOther       = "other"
)

// AuthLog is what the authentication log says over one window.
type AuthLog struct {
	// Window is the period that was read ("24h", "7d").
	Window string
	// Source names where the lines came from ("journalctl -u sshd",
	// "/var/log/auth.log"), so a reader knows what was actually searched.
	Source string
	// Unavailable explains why there is nothing, when there is nothing.
	Unavailable string
	// Accepted, Failed and InvalidUser are the counts over the window.
	Accepted    int
	Failed      int
	InvalidUser int
	// TopIPs and TopUsers are the busiest sources and targets of the failures,
	// most first.
	TopIPs   []Count
	TopUsers []Count
	// Events are the classified lines, newest first.
	Events []AuthEvent
}

// HostKey is one of the server's own key pairs, read from its public half.
type HostKey struct {
	// Path is the public key file.
	Path string
	// Type is the key type as ssh-keygen names it ("ED25519", "RSA").
	Type string
	// Bits is the key size.
	Bits int
	// Fingerprint is the SHA256 fingerprint.
	Fingerprint string
	// Comment is whatever the key carries, often "root@host" or "no comment".
	Comment string
	// Verdict and Note judge the key: a 1024-bit RSA host key is a finding.
	Verdict Verdict
	Note    string
}

// Listener is one socket the server is accepting on.
type Listener struct {
	Address string
	Port    int
	// Process is the program holding the socket, empty when the read was not
	// privileged enough to see it.
	Process string
}

// String renders the listener as `address:port`.
func (l Listener) String() string {
	return l.Address + ":" + strconv.Itoa(l.Port)
}

// Guard is a brute-force blocker found on the machine. tui-ssh only reports
// them: their rules belong to the tool that owns them.
type Guard struct {
	// Name is the program ("fail2ban", "sshguard").
	Name string
	// Unit is the systemd unit that carries it.
	Unit string
	// Active reports whether the unit is running.
	Active bool
	// State is the unit's ActiveState, for the cases Active does not cover.
	State string
}

// Service is the state of the SSH server as a system service.
type Service struct {
	// Unit is the systemd unit name, which is `ssh` on Debian and Ubuntu and
	// `sshd` on Fedora, Arch and openSUSE.
	Unit string
	// Active reports whether it is running; Enabled whether it starts at boot.
	Active  bool
	Enabled bool
	// ActiveState and UnitFileState are systemd's own words, kept for the
	// states the two booleans flatten ("activating", "masked").
	ActiveState   string
	UnitFileState string
	// Since is when the unit entered its current state.
	Since string
	// Listeners are the sockets it is accepting on.
	Listeners []Listener
	// Guards are the brute-force blockers found on the machine.
	Guards []Guard
}

// Model is the whole picture tui-ssh renders.
type Model struct {
	// Backend names the implementation that produced this model.
	Backend string
	// Effective reports that the settings came from `sshd -T`, which is the
	// server's own answer. When it is false the settings were parsed from the
	// files, and are what the files say rather than what sshd concluded.
	Effective bool
	// EffectiveReason explains why `sshd -T` was not used, when it was not.
	EffectiveReason string

	// Settings are the keywords in force: the security-relevant ones first, in
	// a fixed order, then everything else alphabetically.
	Settings []Setting
	// Files are the configuration files, in sshd's reading order.
	Files []ConfigFile

	Service  Service
	Sessions []Session
	Auth     AuthLog
	HostKeys []HostKey

	// Firewall names the firewall that is actually active on this machine
	// ("ufw"), empty when none was found. It decides whether blocking an
	// address is an offer or a hint.
	Firewall string
}

// Setting returns one keyword's setting, matched case-insensitively the way
// sshd matches keywords.
func (m Model) Setting(key string) (Setting, bool) {
	for _, s := range m.Settings {
		if strings.EqualFold(s.Key, key) {
			return s, true
		}
	}
	return Setting{}, false
}

// File returns the parsed configuration file at a path.
func (m Model) File(path string) (ConfigFile, bool) {
	for _, f := range m.Files {
		if f.Path == path {
			return f, true
		}
	}
	return ConfigFile{}, false
}

// Findings are the settings whose verdict is worse than ok, worst first. It is
// what the header counts and what `--check` reports.
func (m Model) Findings() []Setting {
	var out []Setting
	for _, s := range m.Settings {
		if s.Verdict == VerdictRisk || s.Verdict == VerdictWarn {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Verdict == VerdictRisk && out[j].Verdict != VerdictRisk
	})
	return out
}

// Port is the port the server listens on, which is what the session read has
// to filter on. It falls back to 22 when nothing said otherwise.
func (m Model) Port() int {
	if setting, ok := m.Setting("Port"); ok {
		if port, err := strconv.Atoi(strings.Fields(setting.Value)[0]); err == nil &&
			port > 0 && port < 65536 {
			return port
		}
	}
	return DefaultPort
}

// DefaultPort is where sshd listens when nothing says otherwise.
const DefaultPort = 22

// The windows the authentication log can be read over.
const (
	Window24h = "24h"
	Window7d  = "7d"
)

// Capabilities tells the UI what a backend supports, so the key map is built
// from the backend rather than hardcoded.
type Capabilities struct {
	// DropInPath is the file an edit is written to. It is a drop-in, so a
	// hand-written sshd_config is never rewritten.
	DropInPath string
	// SupportsEdit reports whether a setting can be changed at all.
	SupportsEdit bool
	// SupportsTerminate reports whether a session can be terminated.
	SupportsTerminate bool
	// SupportsRegenerateHostKeys reports whether the host keys can be replaced.
	SupportsRegenerateHostKeys bool
	// EditableKeys are the keywords the guided form offers, in the order it
	// offers them.
	EditableKeys []string
	// Choices are the accepted values of a keyword whose values are a closed
	// set; a keyword absent from the map is free text.
	Choices map[string][]string
	// Help is the one sentence the editor shows under a keyword, so the UI
	// explains what a setting does without knowing anything about sshd.
	Help map[string]string
}

// ChoicesFor returns the accepted values of a keyword, and whether it has a
// closed set at all.
func (c Capabilities) ChoicesFor(key string) ([]string, bool) {
	options, ok := c.Choices[key]
	return options, ok && len(options) > 0
}

// WritePlan is a configuration change the user is about to make: what the file
// will look like, how that differs from what is there now, whether the server
// accepted it, and the exact commands that apply it.
type WritePlan struct {
	// Path is the destination file.
	Path string
	// Content is the text that will be installed.
	Content string
	// Diff is the unified diff against the current file, empty when nothing
	// would change.
	Diff string
	// TempPath is the staging file the install command copies from.
	TempPath string
	// Validation is what `sshd -t -f` said about the staged file, and
	// ValidationCommand is the command line that asked. The check runs before
	// the user is asked to confirm, because a syntax error is not something to
	// discover after the file is in /etc.
	Validation        string
	ValidationCommand string
	// Validated reports that the check ran and passed. False with an empty
	// Validation means the check could not run at all.
	Validated bool
	// Warning is a caveat the confirm dialog must show: that the port is
	// changing and the firewall has to allow it, or that another file already
	// sets this keyword earlier and would win.
	Warning string
	// Commands are run in order, and are what the confirm dialog shows.
	Commands []Command
}

// Backend is the boundary between the UI and the machine. Load reads state;
// the Build* methods turn user intent into previewable Commands; Run executes
// a Command the user confirmed. Nothing else may mutate the system.
type Backend interface {
	// Name is the backend identifier ("openssh").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Capabilities reports what this backend supports.
	Capabilities() Capabilities

	// Preview renders the exact command line Run will execute, privilege
	// wrapper included. This is the text shown in the confirm dialog.
	Preview(cmd Command) string

	// Load reads the server's state, with the authentication log over one
	// window.
	Load(ctx context.Context, window string) (Model, error)
	// LoadAuth re-reads only the authentication log, which is what switching
	// the window does.
	LoadAuth(ctx context.Context, model Model, window string) (AuthLog, error)
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd Command) (string, error)

	// BuildSetOption renders the drop-in file that sets a keyword, validates it
	// with the server's own parser and returns the plan that installs it.
	BuildSetOption(model Model, key, value string) (WritePlan, error)
	// BuildReload asks the service to re-read its configuration.
	BuildReload(model Model) (Command, error)
	// BuildTerminateSession ends one login.
	BuildTerminateSession(session Session) (Command, error)
	// BuildRegenerateHostKeys moves the current host keys aside and generates
	// a fresh set. It is several commands, all shown before any of them runs.
	BuildRegenerateHostKeys(model Model) ([]Command, error)
	// BuildDenyIP blocks an address at the firewall. It returns an error
	// naming the reason when no firewall this tool can drive is active, which
	// the UI turns into a hint rather than a dialog.
	BuildDenyIP(model Model, ip string) (Command, error)
}
