package openssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// fixture reads one captured output from testdata.
//
// The captures are real where a real one could be taken on the machine this
// tool was written on: `ssh -V`, `loginctl`, `systemctl show`, `ss -tlnp` and
// `ssh-keygen -lf` all answer to any user, so those files are what that Fedora
// 42 host actually printed, with the account name and one routable network
// rewritten into the documentation ranges.
//
// Two are synthetic, and deliberately so. `sshd -T` needs root and `sudo -n`
// refuses on a workstation whose sudo asks for a password, so sshd-T.txt is
// built from sshd_config(5) and the defaults of the OpenSSH 9.9 on that host;
// /etc/ssh/sshd_config is mode 0600 there for the same reason, so the two
// configuration fixtures are written to the shapes the distributions ship —
// one with its Include first, one with it last, which is the difference the
// whole editor turns on.
func fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(raw)
}

// configTree parses a set of files with no filesystem behind them.
func configTree(files map[string]string, root string) []ssh.ConfigFile {
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
	return ParseConfigTree(read, glob, root)
}

func TestSplitDirective(t *testing.T) {
	// All three separators sshd accepts, plus the comment forms.
	tests := []struct {
		line       string
		key, value string
		ok         bool
	}{
		{"Port 22", "Port", "22", true},
		{"Port=2222", "Port", "2222", true},
		{"Port = 2222", "Port", "2222", true},
		{"\tPermitRootLogin\tno", "PermitRootLogin", "no", true},
		{"AllowUsers ana deploy", "AllowUsers", "ana deploy", true},
		{"Port 22 # the default", "Port", "22", true},
		{"#Port 2222", "", "", false},
		{"   ", "", "", false},
		{"", "", "", false},
	}
	for _, test := range tests {
		key, value, ok := splitDirective(test.line)
		if ok != test.ok || key != test.key || value != test.value {
			t.Errorf("splitDirective(%q) = %q, %q, %v; want %q, %q, %v",
				test.line, key, value, ok, test.key, test.value, test.ok)
		}
	}
}

func TestParseEffective(t *testing.T) {
	settings := ParseEffective(fixture(t, "sshd-T.txt"))
	byKey := map[string]ssh.Setting{}
	for _, setting := range settings {
		byKey[setting.Key] = setting
	}

	for key, want := range map[string]string{
		"PermitRootLogin":              "prohibit-password",
		"PasswordAuthentication":       "yes",
		"KbdInteractiveAuthentication": "yes",
		"MaxAuthTries":                 "6",
		"Port":                         "22",
	} {
		if got := byKey[key].Value; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
		if !byKey[key].Effective {
			t.Errorf("%s did not come back marked as effective", key)
		}
	}

	// A keyword sshd prints once per value — listenaddress, hostkey — is one
	// row, not three, or the table would repeat the keyword and hide the rest.
	if got := byKey["ListenAddress"].Value; got != "[::]:22 0.0.0.0:22" {
		t.Errorf("ListenAddress = %q, want both addresses folded into one row", got)
	}
	if count := strings.Count(byKey["HostKey"].Value, "/etc/ssh/"); count != 3 {
		t.Errorf("HostKey folded %d paths, want 3", count)
	}
}

// TestIncludeOrderDecidesTheWinner is the rule the whole editor turns on: sshd
// takes the first value it is given, so where the Include sits decides whether
// a drop-in wins a keyword or is read and ignored.
func TestIncludeOrderDecidesTheWinner(t *testing.T) {
	dropIn := DropInDir + "/50-distribution.conf"

	first := configTree(map[string]string{
		ConfigPath: fixture(t, "sshd_config-include-first.txt"),
		dropIn:     fixture(t, "50-distribution.conf.txt"),
	}, ConfigPath)
	if len(first) != 2 || first[0].Path != ConfigPath || first[1].Path != dropIn {
		t.Fatalf("include-first order = %v", paths(first))
	}
	settings := SettingsFromFiles(first)
	password := find(t, settings, "PasswordAuthentication")
	winner, ok := password.Winner()
	if !ok || winner.File != dropIn {
		t.Errorf("with the Include first, %s should win; got %v",
			dropIn, winner)
	}
	if password.Value != "no" {
		t.Errorf("PasswordAuthentication = %q, want the drop-in's no", password.Value)
	}

	last := configTree(map[string]string{
		ConfigPath: fixture(t, "sshd_config-include-last.txt"),
		dropIn:     fixture(t, "50-distribution.conf.txt"),
	}, ConfigPath)
	settings = SettingsFromFiles(last)
	password = find(t, settings, "PasswordAuthentication")
	winner, ok = password.Winner()
	if !ok || winner.File != ConfigPath {
		t.Errorf("with the Include last, %s should win; got %v", ConfigPath, winner)
	}
	if !password.Shadowed(dropIn) {
		t.Errorf("a drop-in that cannot win must report itself shadowed")
	}
	if password.Value != "yes" {
		t.Errorf("PasswordAuthentication = %q, want sshd_config's yes", password.Value)
	}
}

// TestMatchBlockNeverWins: a keyword inside a Match block applies to the
// connections that block selects, so it is not the value the table shows.
func TestMatchBlockNeverWins(t *testing.T) {
	files := configTree(map[string]string{
		ConfigPath: fixture(t, "sshd_config-include-first.txt"),
	}, ConfigPath)
	settings := SettingsFromFiles(files)

	chroot := find(t, settings, "ChrootDirectory")
	if _, ok := chroot.Winner(); ok {
		t.Errorf("ChrootDirectory is only set inside a Match block, so nothing wins")
	}
	if len(chroot.Sources) != 1 || chroot.Sources[0].Match != "Group sftponly" {
		t.Errorf("ChrootDirectory sources = %+v", chroot.Sources)
	}

	// AllowTcpForwarding is set both at file scope and inside the block: the
	// file-scope one is the winner, and the block one is still listed.
	forwarding := find(t, settings, "AllowTcpForwarding")
	winner, ok := forwarding.Winner()
	if !ok || winner.Match != "" || forwarding.Value != "yes" {
		t.Errorf("AllowTcpForwarding winner = %+v, value %q", winner, forwarding.Value)
	}
	if len(forwarding.Sources) != 2 {
		t.Errorf("AllowTcpForwarding sources = %d, want the file and the block",
			len(forwarding.Sources))
	}
}

func TestIncludeSite(t *testing.T) {
	files := configTree(map[string]string{
		ConfigPath: fixture(t, "sshd_config-include-first.txt"),
	}, ConfigPath)
	site, ok := IncludeSite(files)
	if !ok {
		t.Fatalf("the Include of %s was not found", DropInDir)
	}
	if site.File != ConfigPath || site.Line != 6 {
		t.Errorf("include site = %v, want %s:6", site, ConfigPath)
	}

	// A configuration with no Include at all: the editor has to say so rather
	// than write a file nothing reads.
	bare := configTree(map[string]string{ConfigPath: "Port 22\n"}, ConfigPath)
	if _, ok := IncludeSite(bare); ok {
		t.Errorf("a configuration with no Include reported one")
	}
}

func TestAttachSourcesAndOrder(t *testing.T) {
	files := configTree(map[string]string{
		ConfigPath: fixture(t, "sshd_config-include-first.txt"),
	}, ConfigPath)
	settings := Order(AttachSources(ParseEffective(fixture(t, "sshd-T.txt")), files))

	// The security-relevant keywords come first, in the fixed order, because
	// the question a reader arrives with is at the top of that list.
	for i, want := range SecurityKeys[:5] {
		if settings[i].Key != want {
			t.Fatalf("row %d = %q, want %q", i, settings[i].Key, want)
		}
		if !settings[i].Security {
			t.Errorf("%s was not marked security-relevant", want)
		}
	}

	// `sshd -T` knows the value; only the files know where it was written.
	root := find(t, settings, "PermitRootLogin")
	winner, ok := root.Winner()
	if !ok || winner.File != ConfigPath || winner.Line != 12 {
		t.Errorf("PermitRootLogin winner = %v, want %s:12", winner, ConfigPath)
	}

	// And a keyword nobody wrote is sshd's own default, which is a fact worth
	// showing rather than a blank cell.
	tcpKeepAlive := find(t, settings, "TCPKeepAlive")
	if !tcpKeepAlive.Default || len(tcpKeepAlive.Sources) != 0 {
		t.Errorf("TCPKeepAlive = %+v, want it marked as a default", tcpKeepAlive)
	}
}

func TestParseLoginctlSessions(t *testing.T) {
	ids := ParseLoginctlSessions(fixture(t, "loginctl-list-sessions.txt"))
	if len(ids) != 2 || ids[0] != "2" || ids[1] != "3" {
		t.Errorf("session ids = %v, want [2 3]", ids)
	}
}

func TestParseShowSession(t *testing.T) {
	session, ok := ParseShowSession(fixture(t, "loginctl-show-session-ssh.txt"))
	if !ok {
		t.Fatalf("an sshd session was not recognised")
	}
	if session.ID != "27" || session.User != "deploy" ||
		session.RemoteIP != "203.0.113.42" || session.TTY != "pts/0" ||
		session.Leader != 4711 || session.State != "active" {
		t.Errorf("session = %+v", session)
	}

	// logind tracks the console and the desktop too, and neither is an SSH
	// login. The captured desktop session is what proves the filter works.
	if _, ok := ParseShowSession(fixture(t, "loginctl-show-session-desktop.txt")); ok {
		t.Errorf("a gdm session was reported as an SSH login")
	}
}

func TestParseSSConnections(t *testing.T) {
	sessions := ParseSSConnections(fixture(t, "ss-established.txt"))
	if len(sessions) != 3 {
		t.Fatalf("parsed %d connections, want 3", len(sessions))
	}
	if sessions[0].RemoteIP != "203.0.113.42" || sessions[0].RemotePort != 51422 ||
		sessions[0].LocalPort != 22 || sessions[0].Leader != 4711 {
		t.Errorf("first connection = %+v", sessions[0])
	}
	// An IPv6 peer carries colons of its own, so the split is on the last one.
	if sessions[2].RemoteIP != "2001:db8:1::9" || sessions[2].RemotePort != 39944 {
		t.Errorf("IPv6 connection = %+v", sessions[2])
	}
}

func TestMergeSessions(t *testing.T) {
	logind := []ssh.Session{
		{ID: "27", User: "deploy", RemoteIP: "203.0.113.42", Leader: 4711},
	}
	sockets := ParseSSConnections(fixture(t, "ss-established.txt"))
	merged := MergeSessions(logind, sockets, 22)

	if len(merged) != 3 {
		t.Fatalf("merged %d sessions, want the logind one plus the two orphans",
			len(merged))
	}
	if merged[0].User != "deploy" || merged[0].RemotePort != 51422 {
		t.Errorf("the logind session did not pick up its socket: %+v", merged[0])
	}
	// A connection logind knows nothing about is still a connection.
	if !strings.Contains(merged[1].User, "no logind") {
		t.Errorf("an orphan socket = %+v, want it labelled", merged[1])
	}
}

func TestParseListeners(t *testing.T) {
	listeners := ParseListeners(fixture(t, "ss-listen.txt"))
	var found bool
	for _, listener := range listeners {
		if listener.Address == "0.0.0.0" && listener.Port == 22 {
			found = true
		}
	}
	if !found {
		t.Errorf("the sshd socket was not parsed out of %v", listeners)
	}
	// The process column is only there for a privileged read; a line without
	// one must still parse rather than be dropped.
	for _, listener := range listeners {
		if listener.Port == 6190 && listener.Process != "cef_server" {
			t.Errorf("process column = %q", listener.Process)
		}
	}
}

func TestParseProperties(t *testing.T) {
	properties := ParseProperties(fixture(t, "systemctl-show-sshd.txt"))
	if properties["ActiveState"] != "active" ||
		properties["UnitFileState"] != "enabled" ||
		properties["LoadState"] != "loaded" {
		t.Errorf("properties = %v", properties)
	}
}

func TestParseFingerprint(t *testing.T) {
	tests := map[string]struct {
		typ     string
		bits    int
		comment string
	}{
		"ssh-keygen-ed25519.txt": {"ED25519", 256, "no comment"},
		"ssh-keygen-rsa.txt":     {"RSA", 2048, "root@demo"},
		"ssh-keygen-ecdsa.txt":   {"ECDSA", 256, "root@demo"},
	}
	for name, want := range tests {
		key, ok := ParseFingerprint("/etc/ssh/x.pub", fixture(t, name))
		if !ok {
			t.Fatalf("%s did not parse", name)
		}
		if key.Type != want.typ || key.Bits != want.bits || key.Comment != want.comment {
			t.Errorf("%s = %+v, want %v", name, key, want)
		}
		if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
			t.Errorf("%s fingerprint = %q", name, key.Fingerprint)
		}
	}
}

func TestParseAuthLog(t *testing.T) {
	log := ParseAuthLog(fixture(t, "auth-journal.txt"), ssh.Window24h, "journalctl")

	if log.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", log.Accepted)
	}
	// "Failed password", "maximum authentication attempts" — and the two
	// "Failed password for invalid user" lines, which are failures that also
	// name an account that does not exist.
	if log.Failed != 4 {
		t.Errorf("failed = %d, want 4", log.Failed)
	}
	// The standalone "Invalid user" line is what is counted as one, so the
	// pair sshd writes for a bad account is not double counted as a failure.
	if log.InvalidUser != 2 {
		t.Errorf("invalid user = %d, want 2", log.InvalidUser)
	}

	if len(log.TopIPs) == 0 || log.TopIPs[0].Name != "203.0.113.7" {
		t.Errorf("top addresses = %v", log.TopIPs)
	}
	// Newest first: what a reader wants on opening the screen is what just
	// happened, and both sources print oldest first.
	if !strings.Contains(log.Events[0].Raw, "backup") {
		t.Errorf("first event = %q, want the most recent", log.Events[0].Raw)
	}

	accepted := log.Events[0]
	if accepted.Kind != ssh.AuthAccepted || accepted.User != "backup" ||
		accepted.IP != "192.0.2.10" || accepted.Method != "password" {
		t.Errorf("accepted event = %+v", accepted)
	}
}

// find returns a setting by keyword, failing the test when it is missing.
func find(t *testing.T, settings []ssh.Setting, key string) ssh.Setting {
	t.Helper()
	for _, setting := range settings {
		if strings.EqualFold(setting.Key, key) {
			return setting
		}
	}
	t.Fatalf("no setting named %q", key)
	return ssh.Setting{}
}

// paths names the files of a tree, for a failure message.
func paths(files []ssh.ConfigFile) []string {
	var out []string
	for _, file := range files {
		out = append(out, file.Path)
	}
	return out
}
