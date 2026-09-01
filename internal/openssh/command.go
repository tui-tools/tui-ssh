package openssh

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The version-gated capabilities of the backend, named the way the manifest
// names them. A tool asks the compat set for these instead of comparing
// version numbers in the code.
const (
	// FeatureIncludeDropins is the `Include` keyword, which arrived in
	// OpenSSH 8.2 and is what makes a drop-in file possible at all. Without it
	// the only way to change a setting is to rewrite sshd_config, which this
	// tool will not do.
	FeatureIncludeDropins = "include-dropins"
	// FeatureKbdInteractive is `KbdInteractiveAuthentication`, the 8.7 name of
	// what was `ChallengeResponseAuthentication`. Both spellings are read; the
	// one that is written depends on this.
	FeatureKbdInteractive = "kbd-interactive"
)

// The files this backend reads and the one it writes.
const (
	// ConfigPath is the server's main configuration file.
	ConfigPath = "/etc/ssh/sshd_config"
	// DropInDir is where the distributions put the included fragments.
	DropInDir = "/etc/ssh/sshd_config.d"
	// DropInName is the file tui-ssh owns. The 90 prefix puts it after the
	// fragments a distribution ships, which matters for the keywords that
	// accumulate rather than take the first value.
	DropInName = "90-tui-ssh.conf"
	// DropInPath is that file, in full. It is the only path this tool writes.
	DropInPath = DropInDir + "/" + DropInName
	// HostKeyDir is where the server keeps its own key pairs.
	HostKeyDir = "/etc/ssh"
)

// FileMode is the mode a written drop-in gets. It is 600 rather than 644
// because the file can carry an AllowUsers list, and because Fedora and Arch
// ship sshd_config itself that way.
const FileMode = "600"

// ChallengeResponseKey is the pre-8.7 spelling of KbdInteractiveAuthentication.
// It is still accepted as a deprecated alias, and is what an older sshd wants.
const ChallengeResponseKey = "ChallengeResponseAuthentication"

// KbdInteractiveKey is the 8.7 spelling.
const KbdInteractiveKey = "KbdInteractiveAuthentication"

// yesNo is the value set of the many keywords that are a plain boolean.
var yesNo = []string{"yes", "no"}

// option describes one keyword the guided editor can set: the values it
// accepts, and the sentence the form shows under it.
type option struct {
	// choices is the closed set of values, nil for a free-text keyword.
	choices []string
	// pattern validates a free-text value. Every editable keyword has either
	// choices or a pattern: a value that reaches a file in /etc is never taken
	// on trust.
	pattern *regexp.Regexp
	// help is the one line the form shows under the field.
	help string
}

// portRe accepts a TCP port. The range is checked separately, because a regex
// that also spells out 1–65535 is unreadable.
var portRe = regexp.MustCompile(`^[0-9]{1,5}$`)

// numberRe accepts a plain count (MaxAuthTries, ClientAliveInterval).
var numberRe = regexp.MustCompile(`^[0-9]{1,6}$`)

// graceRe accepts LoginGraceTime, which is seconds or systemd-style time.
var graceRe = regexp.MustCompile(`^[0-9]{1,6}[smh]?$`)

// nameListRe accepts the space-separated user and group patterns AllowUsers and
// AllowGroups take, including the `user@host` form and the `*` and `?` globs.
var nameListRe = regexp.MustCompile(`^[A-Za-z0-9_*?.@:%!-][A-Za-z0-9_*?.@: %!-]*$`)

// listenRe accepts a ListenAddress: an address, optionally with a port.
var listenRe = regexp.MustCompile(`^[0-9A-Fa-f:.\[\]*]+(:[0-9]{1,5})?$`)

// editable is the keyword set the guided editor offers, in the order it offers
// them: the ones that decide who gets in, then the ones that decide how.
//
// It is deliberately a short list. Everything else in sshd_config is shown,
// with its value and the file that set it, and left to an editor — a form that
// claimed to cover every keyword would be a worse editor than vi, and a form
// that silently dropped one would be a trap.
var editable = map[string]option{
	"PermitRootLogin": {
		choices: []string{"no", "prohibit-password", "forced-commands-only", "yes"},
		help: "prohibit-password lets root in by key only; " +
			"no keeps root out entirely.",
	},
	"PasswordAuthentication": {choices: yesNo,
		help: "no is the setting that ends password guessing against this host."},
	"PubkeyAuthentication": {choices: yesNo,
		help: "Turning this off leaves passwords as the only way in."},
	KbdInteractiveKey: {choices: yesNo,
		help: "PAM's interactive prompts, which include passwords on many hosts."},
	"PermitEmptyPasswords": {choices: yesNo,
		help: "yes lets an account with no password log in. There is no good reason."},
	"X11Forwarding": {choices: yesNo,
		help: "Forwarding X gives the client a path back into your session."},
	"AllowTcpForwarding": {choices: []string{"no", "yes", "local", "remote"},
		help: "no stops this host being used as a tunnel."},
	"UsePAM": {choices: yesNo,
		help: "PAM runs the account and session stack. Most distributions need it."},
	"Port": {pattern: portRe,
		help: "The port sshd listens on. The firewall has to allow it."},
	"MaxAuthTries": {pattern: numberRe,
		help: "Attempts per connection before it is dropped. 3 is a good number."},
	"LoginGraceTime": {pattern: graceRe,
		help: "How long an unauthenticated connection may sit. Seconds, or 30s / 2m."},
	"ClientAliveInterval": {pattern: numberRe,
		help: "Seconds between keepalives; 0 turns them off."},
	"ClientAliveCountMax": {pattern: numberRe,
		help: "Missed keepalives before the session is dropped."},
	"AllowUsers": {pattern: nameListRe,
		help: "Space-separated user patterns. Setting it denies everyone else."},
	"AllowGroups": {pattern: nameListRe,
		help: "Space-separated group patterns. Setting it denies everyone else."},
	"ListenAddress": {pattern: listenRe,
		help: "The address to accept on; the firewall has to allow it."},
}

// editableOrder is the order the editor offers the keywords in. A map has no
// order, and the form's field list must not shuffle between runs.
var editableOrder = []string{
	"PermitRootLogin",
	"PasswordAuthentication",
	"PubkeyAuthentication",
	KbdInteractiveKey,
	"PermitEmptyPasswords",
	"MaxAuthTries",
	"LoginGraceTime",
	"Port",
	"ListenAddress",
	"AllowUsers",
	"AllowGroups",
	"X11Forwarding",
	"AllowTcpForwarding",
	"UsePAM",
	"ClientAliveInterval",
	"ClientAliveCountMax",
}

// capabilities describes what the openssh backend supports. It is shared by the
// real and the fake backend, so --demo behaves exactly like a real run.
var capabilities = ssh.Capabilities{
	DropInPath:                 DropInPath,
	SupportsEdit:               true,
	SupportsTerminate:          true,
	SupportsRegenerateHostKeys: true,
	SupportsAuthorizedKeys:     true,
	SupportsMatch:              true,
	MatchTypes:                 MatchTypes,
	EditableKeys:               editableOrder,
	Choices:                    choiceMap(),
	Help:                       helpMap(),
}

// choiceMap exposes the closed value sets to the UI, which builds the form's
// pickers from them rather than carrying a second copy.
func choiceMap() map[string][]string {
	out := map[string][]string{}
	for key, spec := range editable {
		if len(spec.choices) > 0 {
			out[key] = spec.choices
		}
	}
	return out
}

// helpMap exposes the per-keyword sentence to the UI, so the form can explain
// a setting without knowing what sshd is.
func helpMap() map[string]string {
	out := map[string]string{}
	for key, spec := range editable {
		out[key] = spec.help
	}
	return out
}

// Capabilities reports what the openssh backend supports.
func Capabilities() ssh.Capabilities { return capabilities }

// HelpFor returns the one-line hint the form shows for a keyword.
func HelpFor(key string) string { return editable[canonicalKey(key)].help }

// canonicalKey maps a keyword onto the spelling this package uses, which is
// sshd's own. `sshd -T` lower-cases everything it prints, and a file can be
// written in any case at all, so every lookup goes through here.
func canonicalKey(key string) string {
	if canonical, ok := canonicalKeys[strings.ToLower(key)]; ok {
		return canonical
	}
	return key
}

// canonicalKeys is built once from every keyword this package names.
var canonicalKeys = buildCanonicalKeys()

func buildCanonicalKeys() map[string]string {
	out := map[string]string{}
	for _, key := range Keywords {
		out[strings.ToLower(key)] = key
	}
	// The keywords this package names itself are added after the manual page's
	// list, so a spelling used in the code always wins over one that drifted.
	for _, key := range editableOrder {
		out[strings.ToLower(key)] = key
	}
	for _, key := range SecurityKeys {
		out[strings.ToLower(key)] = key
	}
	return out
}

// CheckValue validates a value for a keyword the editor offers. It is the same
// check the file renderer runs, so the form cannot approve something the
// renderer would refuse.
func CheckValue(key, value string) error {
	key = canonicalKey(key)
	spec, ok := editable[key]
	if !ok {
		return fmt.Errorf("openssh: tui-ssh does not edit %s; "+
			"change it in %s and reload", key, ConfigPath)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("openssh: %s needs a value", key)
	}
	// A value goes into a file, so a newline would smuggle in a second
	// directive and a `#` would comment the rest of the line out. Neither is
	// something a guided form should be able to produce.
	if strings.ContainsAny(value, "\n\r#") {
		return fmt.Errorf("openssh: a %s value cannot contain a newline or a #", key)
	}
	if len(spec.choices) > 0 {
		for _, choice := range spec.choices {
			if value == choice {
				return nil
			}
		}
		return fmt.Errorf("openssh: %s must be one of %s",
			key, strings.Join(spec.choices, ", "))
	}
	if !spec.pattern.MatchString(value) {
		return fmt.Errorf("openssh: %q is not a value %s takes", value, key)
	}
	if key == "Port" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("openssh: a port is between 1 and 65535")
		}
	}
	return nil
}

// WriteKeyFor picks the spelling to write for a keyword, which is only ever a
// question for the one keyword OpenSSH renamed: an sshd older than 8.7 knows
// KbdInteractiveAuthentication by its old name and refuses the new one.
func WriteKeyFor(key string, hasKbdInteractive bool) string {
	key = canonicalKey(key)
	if key == KbdInteractiveKey && !hasKbdInteractive {
		return ChallengeResponseKey
	}
	return key
}

// dropInHeader is the banner the generated file always carries. It names the
// tool, and it states the one rule a reader of this file has to know.
const dropInHeader = "# Written by tui-ssh, and rewritten whole on every change.\n" +
	"# sshd takes the FIRST value it is given for a keyword, so a keyword set\n" +
	"# above this file's Include in " + ConfigPath + " wins over what is here.\n"

// RenderDropIn produces the new text of the drop-in file: everything it says
// today, with one keyword set or replaced at file scope.
//
// The whole file is regenerated rather than appended to, because a drop-in that
// grew by appending would end up with the same keyword three times and sshd
// would silently use the first — which is exactly the confusion this tool
// exists to remove.
func RenderDropIn(existing, key, value string) (string, error) {
	key = canonicalKey(key)
	if err := CheckValue(key, value); err != nil {
		return "", err
	}
	blocks := parseDropInBlocks(existing)
	blocks[0].settings = setSetting(blocks[0].settings, key, value)
	return renderDropInBlocks(blocks), nil
}

// RenderMatchDropIn produces the new text of the drop-in file with one keyword
// set inside a `Match` block.
//
// The block goes at the end, and every Match block stays at the end, because
// that is not a style choice: sshd reads everything following a Match line as
// part of that block until the next Match or the end of the file. A keyword
// written at file scope *after* a Match block would silently become part of it,
// applying to some connections and not to others — so the renderer keeps the
// whole file in the one order that means what it says.
func RenderMatchDropIn(existing, matchType, matchValue, key, value string) (string, error) {
	criteria, err := MatchCriteria(matchType, matchValue)
	if err != nil {
		return "", err
	}
	key = canonicalKey(key)
	if err := CheckValue(key, value); err != nil {
		return "", err
	}

	blocks := parseDropInBlocks(existing)
	for i := 1; i < len(blocks); i++ {
		if strings.EqualFold(blocks[i].criteria, criteria) {
			blocks[i].settings = setSetting(blocks[i].settings, key, value)
			return renderDropInBlocks(blocks), nil
		}
	}
	blocks = append(blocks, dropInBlock{
		criteria: criteria,
		settings: []dropInSetting{{key: key, value: value}},
	})
	return renderDropInBlocks(blocks), nil
}

// setSetting replaces a keyword's value, or appends it when the block does not
// carry it yet.
func setSetting(settings []dropInSetting, key, value string) []dropInSetting {
	for i := range settings {
		if strings.EqualFold(settings[i].key, key) {
			settings[i] = dropInSetting{key: key, value: value}
			return settings
		}
	}
	return append(settings, dropInSetting{key: key, value: value})
}

// dropInSetting is one keyword of the generated file.
type dropInSetting struct{ key, value string }

// dropInBlock is one scope of the generated file: the file scope, whose
// criteria is empty, or one `Match` block.
type dropInBlock struct {
	criteria string
	settings []dropInSetting
}

// matchIndent is what a keyword inside a Match block is written with. sshd does
// not care; a reader opening the file does.
const matchIndent = "    "

// renderDropInBlocks writes the file: the banner, the file-scope keywords, then
// every Match block. The order is the contract — see RenderMatchDropIn.
func renderDropInBlocks(blocks []dropInBlock) string {
	var b strings.Builder
	b.WriteString(dropInHeader)
	b.WriteString("\n")
	for _, setting := range blocks[0].settings {
		fmt.Fprintf(&b, "%s %s\n", setting.key, setting.value)
	}
	for _, block := range blocks[1:] {
		if len(block.settings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\nMatch %s\n", block.criteria)
		for _, setting := range block.settings {
			fmt.Fprintf(&b, "%s%s %s\n", matchIndent, setting.key, setting.value)
		}
	}
	return b.String()
}

// parseDropIn reads the file-scope keywords out of the file tui-ssh wrote last
// time. It ignores comments, because the file is generated and its only
// comments are the banner this package puts back.
func parseDropIn(text string) []dropInSetting {
	return parseDropInBlocks(text)[0].settings
}

// parseDropInBlocks reads the generated file into its scopes. The first block
// is always the file scope, even when the file is empty, so a caller can set a
// keyword on it without checking.
func parseDropInBlocks(text string) []dropInBlock {
	blocks := []dropInBlock{{}}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		if strings.EqualFold(key, "Match") {
			blocks = append(blocks, dropInBlock{criteria: value})
			continue
		}
		current := &blocks[len(blocks)-1]
		current.settings = append(current.settings,
			dropInSetting{key: canonicalKey(key), value: value})
	}
	return blocks
}

// The criteria a Match block can select on, in the order the form offers them.
//
// sshd accepts more of them — LocalAddress, LocalPort, RDomain, and the
// all-caps All — but these three are the ones an administrator reaches for, and
// each is a value this tool can check before writing it. A criteria that cannot
// be validated is not one a guided form should be able to produce.
const (
	MatchUser    = "User"
	MatchGroup   = "Group"
	MatchAddress = "Address"
)

// MatchTypes is that list, in the order the form offers it.
var MatchTypes = []string{MatchUser, MatchGroup, MatchAddress}

// matchNameRe accepts one user or group pattern of a Match criteria: the same
// character set AllowUsers takes, with the globs sshd itself expands.
var matchNameRe = regexp.MustCompile(`^[A-Za-z0-9_*?.@-]{1,64}$`)

// MatchCriteria validates a criteria and renders it as sshd writes it.
//
// The value is a comma-separated list, which is sshd's own grammar: `Match User
// ana,deploy` selects either. Each item is checked on its own, and an address
// item is parsed as an address or a network rather than pattern-matched, so
// `Match Address 10.0` — which looks fine and selects nothing — is refused here
// instead of being discovered later.
func MatchCriteria(matchType, matchValue string) (string, error) {
	canonical := ""
	for _, candidate := range MatchTypes {
		if strings.EqualFold(candidate, matchType) {
			canonical = candidate
		}
	}
	if canonical == "" {
		return "", fmt.Errorf("openssh: a Match block selects on %s, not %q",
			strings.Join(MatchTypes, ", "), matchType)
	}

	value := strings.TrimSpace(matchValue)
	if value == "" {
		return "", fmt.Errorf("openssh: Match %s needs a value", canonical)
	}
	if strings.ContainsAny(value, "\n\r# \t") {
		return "", fmt.Errorf(
			"openssh: a Match %s value is one comma-separated list, with no "+
				"spaces and no comment", canonical)
	}
	items := strings.Split(value, ",")
	if len(items) > maxMatchItems {
		return "", fmt.Errorf("openssh: %d is more patterns than this form writes",
			len(items))
	}
	for _, item := range items {
		if err := checkMatchItem(canonical, item); err != nil {
			return "", err
		}
	}
	return canonical + " " + value, nil
}

// maxMatchItems bounds the comma-separated list, so a paste cannot turn into a
// line nothing on the confirm dialog can show in full.
const maxMatchItems = 32

// checkMatchItem validates one item of a criteria's list.
func checkMatchItem(matchType, item string) error {
	if matchType != MatchAddress {
		if !matchNameRe.MatchString(item) {
			return fmt.Errorf("openssh: %q is not a %s pattern",
				item, strings.ToLower(matchType))
		}
		return nil
	}
	// sshd negates an address pattern with a leading '!', which is part of the
	// grammar rather than part of the address.
	address := strings.TrimPrefix(item, "!")
	if address == "*" {
		return nil
	}
	if strings.Contains(address, "/") {
		if _, err := netip.ParsePrefix(address); err != nil {
			return fmt.Errorf("openssh: %q is not a network in CIDR form", item)
		}
		return nil
	}
	if _, err := netip.ParseAddr(address); err != nil {
		return fmt.Errorf("openssh: %q is not an IP address or a CIDR network", item)
	}
	return nil
}

// unitRe is the set of characters a systemd unit name may contain. The unit
// comes from the machine and ends up in an argv, so it is checked like every
// other value that makes that trip.
var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,64}$`)

// BuildReload asks the service to re-read its configuration. Reload rather than
// restart: sshd re-execs on SIGHUP and picks up both the configuration and the
// host keys, and the sessions already open survive it.
func BuildReload(unit string) (ssh.Command, error) {
	if !unitRe.MatchString(unit) {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not a unit name", unit)
	}
	return ssh.Command{
		Argv:        []string{"systemctl", "reload", unit},
		Description: "Reload " + unit + " so it re-reads its configuration",
	}, nil
}

// stagedRe accepts the staging path the install command copies from. It is a
// path this package built, and it is checked anyway.
var stagedRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// BuildInstallDropIn copies a staged file into the drop-in directory.
// `install` is used rather than `cp` because it sets the mode in the same call,
// so there is no window where the file is on disk world-readable.
func BuildInstallDropIn(tempPath string) (ssh.Command, error) {
	if !stagedRe.MatchString(tempPath) {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not a staging path", tempPath)
	}
	// `install` is run through the privilege prefix, so the file it creates is
	// already root's: naming the owner again would only make the preview
	// longer, and the preview is the thing a user has to read.
	return ssh.Command{
		Argv:        []string{"install", "-m", FileMode, tempPath, DropInPath},
		Description: "Install " + tempPath + " as " + DropInPath,
		Destructive: true,
	}, nil
}

// BuildValidate asks sshd to parse a staged file. It is a read: it prints
// what it thinks of the file and exits, and it is the reason a bad value never
// reaches /etc.
//
// It checks the staged drop-in on its own rather than the merged configuration,
// because merging would mean copying /etc/ssh/sshd_config somewhere writable
// first. What it proves is what the confirm dialog claims and no more: sshd on
// this machine accepts these keywords and these values.
func BuildValidate(tempPath string) (ssh.Command, error) {
	if !stagedRe.MatchString(tempPath) {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not a staging path", tempPath)
	}
	return ssh.Command{
		Argv:        []string{"sshd", "-t", "-f", tempPath},
		Description: "Check " + tempPath + " with the server's own parser",
	}, nil
}

// sessionRe is the shape of a logind session id.
var sessionRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// BuildTerminateSession ends one login.
func BuildTerminateSession(session ssh.Session) (ssh.Command, error) {
	if !sessionRe.MatchString(session.ID) {
		return ssh.Command{}, fmt.Errorf(
			"openssh: this connection has no logind session to terminate")
	}
	return ssh.Command{
		Argv: []string{"loginctl", "terminate-session", session.ID},
		Description: fmt.Sprintf("End session %s: %s from %s",
			session.ID, session.User, session.RemoteIP),
		Destructive: true,
	}, nil
}

// hostKeyRe accepts a host key path: the server's own directory, and the name
// pattern ssh-keygen -A generates.
var hostKeyRe = regexp.MustCompile(
	`^` + HostKeyDir + `/ssh_host_[a-z0-9_]{1,16}_key(\.pub)?$`)

// stampRe accepts the timestamp that names the backup directory.
var stampRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)

// BackupDirFor is where the old host keys are moved to.
func BackupDirFor(stamp string) string {
	return HostKeyDir + "/tui-ssh-hostkeys-" + stamp
}

// BuildRegenerateHostKeys moves the current host keys aside and generates a
// fresh set, then reloads the service so it serves them.
//
// The old keys are moved rather than deleted, so a regeneration done by mistake
// is recoverable: the pairs are in one directory, and putting them back is a
// `mv` the user can read. Every client that has connected before will still
// refuse the new keys until its known_hosts entry is removed, which is what the
// confirm dialog says in as many words.
func BuildRegenerateHostKeys(keys []ssh.HostKey, unit, stamp string) ([]ssh.Command, error) {
	if !stampRe.MatchString(stamp) {
		return nil, fmt.Errorf("openssh: %q is not a backup timestamp", stamp)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("openssh: this machine has no host keys to replace")
	}

	var paths []string
	for _, key := range keys {
		if !hostKeyRe.MatchString(key.Path) {
			return nil, fmt.Errorf("openssh: %q is not a host key path", key.Path)
		}
		private := strings.TrimSuffix(key.Path, ".pub")
		paths = append(paths, private, key.Path)
	}
	sort.Strings(paths)

	backup := BackupDirFor(stamp)
	reload, err := BuildReload(unit)
	if err != nil {
		return nil, err
	}
	return []ssh.Command{
		{
			Argv:        []string{"install", "-d", "-m", "700", backup},
			Description: "Create " + backup + " to hold the current host keys",
			Destructive: true,
		},
		{
			Argv:        append(append([]string{"mv", "--"}, paths...), backup+"/"),
			Description: fmt.Sprintf("Move the %d current host key files into %s", len(paths), backup),
			Destructive: true,
		},
		{
			Argv:        []string{"ssh-keygen", "-A"},
			Description: "Generate a fresh host key for every type this sshd supports",
			Destructive: true,
		},
		reload,
	}, nil
}

// BuildDenyIP blocks an address at the firewall.
//
// ufw is the only firewall this tool will drive, and only when it is the one
// actually running: a `ufw deny` on a machine whose rules are nftables or
// firewalld writes a rule into a firewall nobody is using, which is worse than
// doing nothing because it looks like it worked.
func BuildDenyIP(firewall, ip string) (ssh.Command, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not an IP address", ip)
	}
	if firewall != FirewallUFW {
		return ssh.Command{}, fmt.Errorf(
			"no ufw on this machine to block %s with — "+
				"tui-firewall drives the one you do have", address)
	}
	return ssh.Command{
		Argv:        []string{"ufw", "deny", "from", address.String()},
		Description: "Block every connection from " + address.String(),
		Destructive: true,
	}, nil
}

// FirewallUFW is the one firewall BuildDenyIP knows how to drive.
const FirewallUFW = "ufw"
