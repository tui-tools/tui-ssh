package openssh

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

func TestBuildReload(t *testing.T) {
	// The unit name differs between distributions — `ssh` on Debian and
	// Ubuntu, `sshd` everywhere else — so it is read from the machine and both
	// have to build.
	for unit, want := range map[string]string{
		"sshd": "systemctl reload sshd",
		"ssh":  "systemctl reload ssh",
	} {
		cmd, err := BuildReload(unit)
		if err != nil {
			t.Fatalf("%s: %v", unit, err)
		}
		if got := cmd.String(); got != want {
			t.Errorf("argv %q, want %q", got, want)
		}
		if cmd.Description == "" {
			t.Errorf("a command with no description cannot be confirmed")
		}
	}

	// The unit comes from the machine and ends up in an argv, so anything that
	// is not a unit name is refused before a command exists at all.
	for _, bad := range []string{"", "sshd; reboot", "../../etc", "ssh d"} {
		if _, err := BuildReload(bad); err == nil {
			t.Errorf("BuildReload accepted %q", bad)
		}
	}
}

func TestBuildInstallDropIn(t *testing.T) {
	cmd, err := BuildInstallDropIn("/tmp/tui-ssh-42/90-tui-ssh.conf")
	if err != nil {
		t.Fatalf("BuildInstallDropIn: %v", err)
	}
	want := "install -m 600 /tmp/tui-ssh-42/90-tui-ssh.conf " + DropInPath
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	if !cmd.Destructive {
		t.Errorf("overwriting a configuration file is a destructive change")
	}

	// The destination is not a parameter at all: there is exactly one file
	// this tool writes, and no input can move it.
	if !strings.HasSuffix(cmd.String(), DropInPath) {
		t.Errorf("the install destination is not %s", DropInPath)
	}
	for _, bad := range []string{"", "relative/path", "/tmp/x;reboot", "/tmp/a b"} {
		if _, err := BuildInstallDropIn(bad); err == nil {
			t.Errorf("BuildInstallDropIn accepted %q", bad)
		}
	}
}

func TestBuildValidate(t *testing.T) {
	cmd, err := BuildValidate("/tmp/tui-ssh-42/90-tui-ssh.conf")
	if err != nil {
		t.Fatalf("BuildValidate: %v", err)
	}
	want := "sshd -t -f /tmp/tui-ssh-42/90-tui-ssh.conf"
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	if cmd.Destructive {
		t.Errorf("a syntax check is a read and must not be marked destructive")
	}
}

func TestBuildTerminateSession(t *testing.T) {
	cmd, err := BuildTerminateSession(ssh.Session{
		ID: "27", User: "deploy", RemoteIP: "203.0.113.42"})
	if err != nil {
		t.Fatalf("BuildTerminateSession: %v", err)
	}
	if got := cmd.String(); got != "loginctl terminate-session 27" {
		t.Errorf("argv %q", got)
	}
	if !cmd.Destructive {
		t.Errorf("ending somebody's session is a destructive change")
	}

	// A connection logind knows nothing about has no session to end, and the
	// refusal has to happen here rather than in a command that would fail.
	for _, bad := range []string{"", "27; reboot", "../27"} {
		if _, err := BuildTerminateSession(ssh.Session{ID: bad}); err == nil {
			t.Errorf("BuildTerminateSession accepted %q", bad)
		}
	}
}

func TestBuildRegenerateHostKeys(t *testing.T) {
	keys := []ssh.HostKey{
		{Path: "/etc/ssh/ssh_host_ed25519_key.pub"},
		{Path: "/etc/ssh/ssh_host_rsa_key.pub"},
	}
	commands, err := BuildRegenerateHostKeys(keys, "sshd", "20260829-114500")
	if err != nil {
		t.Fatalf("BuildRegenerateHostKeys: %v", err)
	}
	if len(commands) != 4 {
		t.Fatalf("built %d commands, want the mkdir, the mv, the keygen and the reload",
			len(commands))
	}

	backup := BackupDirFor("20260829-114500")
	want := []string{
		"install -d -m 700 " + backup,
		"mv -- /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub " +
			"/etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key.pub " + backup + "/",
		"ssh-keygen -A",
		"systemctl reload sshd",
	}
	for i, cmd := range commands {
		if got := cmd.String(); got != want[i] {
			t.Errorf("command %d = %q, want %q", i, got, want[i])
		}
	}
	// The old keys are moved, never removed: there is no rm in the plan, and
	// that is what makes a regeneration done by mistake recoverable.
	for _, cmd := range commands {
		if cmd.Argv[0] == "rm" {
			t.Errorf("the plan deletes a key: %q", cmd.String())
		}
	}

	// Every path in that mv is run as root, so a path that is not a host key
	// stops the plan being built at all.
	for _, bad := range []string{"/etc/passwd", "/etc/ssh/../passwd",
		"/etc/ssh/ssh_host_rsa_key.pub.bak"} {
		if _, err := BuildRegenerateHostKeys([]ssh.HostKey{{Path: bad}},
			"sshd", "20260829-114500"); err == nil {
			t.Errorf("BuildRegenerateHostKeys accepted %q", bad)
		}
	}
	if _, err := BuildRegenerateHostKeys(keys, "sshd", "yesterday"); err == nil {
		t.Errorf("BuildRegenerateHostKeys accepted a free-text timestamp")
	}
	if _, err := BuildRegenerateHostKeys(nil, "sshd", "20260829-114500"); err == nil {
		t.Errorf("a machine with no host keys has nothing to regenerate")
	}
}

func TestBuildDenyIP(t *testing.T) {
	cmd, err := BuildDenyIP(FirewallUFW, "203.0.113.7")
	if err != nil {
		t.Fatalf("BuildDenyIP: %v", err)
	}
	if got := cmd.String(); got != "ufw deny from 203.0.113.7" {
		t.Errorf("argv %q", got)
	}

	// A ufw rule on a machine whose firewall is nftables or firewalld writes
	// into a firewall nobody is using, which looks like it worked. So it is
	// refused, and the refusal names the tool that owns the real one.
	_, err = BuildDenyIP("", "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "tui-firewall") {
		t.Errorf("with no ufw running the error should point at tui-firewall: %v", err)
	}
	for _, bad := range []string{"", "not-an-address", "203.0.113.7; reboot",
		"$(id)"} {
		if _, err := BuildDenyIP(FirewallUFW, bad); err == nil {
			t.Errorf("BuildDenyIP accepted %q", bad)
		}
	}
}

func TestCheckValue(t *testing.T) {
	ok := map[string]string{
		"PermitRootLogin":        "prohibit-password",
		"PasswordAuthentication": "no",
		"Port":                   "2222",
		"MaxAuthTries":           "3",
		"LoginGraceTime":         "30s",
		"AllowUsers":             "ana deploy",
		"ListenAddress":          "192.0.2.10",
	}
	for key, value := range ok {
		if err := CheckValue(key, value); err != nil {
			t.Errorf("CheckValue(%s, %q) = %v", key, value, err)
		}
	}

	bad := map[string]string{
		// A value that is not one sshd takes.
		"PermitRootLogin":        "maybe",
		"PasswordAuthentication": "off",
		"Port":                   "70000",
		"MaxAuthTries":           "three",
		// A newline would smuggle a second directive into the file, and a #
		// would comment out the rest of the line. Neither is something a
		// guided form should be able to produce.
		"AllowUsers":     "ana\nPermitRootLogin yes",
		"LoginGraceTime": "30 # and",
		// A keyword the editor does not offer at all.
		"ForceCommand": "/bin/true",
	}
	for key, value := range bad {
		if err := CheckValue(key, value); err == nil {
			t.Errorf("CheckValue(%s, %q) accepted it", key, value)
		}
	}

	// Keywords are matched the way sshd matches them.
	if err := CheckValue("permitrootlogin", "no"); err != nil {
		t.Errorf("a lower-cased keyword was refused: %v", err)
	}
}

func TestWriteKeyForRenamedKeyword(t *testing.T) {
	// OpenSSH renamed ChallengeResponseAuthentication to
	// KbdInteractiveAuthentication in 8.7. An older sshd refuses the new name,
	// so the version decides which spelling is written.
	if got := WriteKeyFor(KbdInteractiveKey, true); got != KbdInteractiveKey {
		t.Errorf("on 8.7 and later = %q, want %q", got, KbdInteractiveKey)
	}
	if got := WriteKeyFor(KbdInteractiveKey, false); got != ChallengeResponseKey {
		t.Errorf("before 8.7 = %q, want %q", got, ChallengeResponseKey)
	}
	// Every other keyword is unaffected by the rename.
	if got := WriteKeyFor("PermitRootLogin", false); got != "PermitRootLogin" {
		t.Errorf("PermitRootLogin = %q", got)
	}
}

func TestRenderDropIn(t *testing.T) {
	first, err := RenderDropIn("", "PasswordAuthentication", "no")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if !strings.Contains(first, "PasswordAuthentication no\n") {
		t.Errorf("rendered file is missing the setting:\n%s", first)
	}
	if !strings.Contains(first, "Written by tui-ssh") {
		t.Errorf("the generated file does not name the tool that wrote it")
	}
	// The rule a reader of this file has to know is in the file itself.
	if !strings.Contains(first, "FIRST value") {
		t.Errorf("the banner does not state sshd's first-value rule:\n%s", first)
	}

	// A second keyword joins the first rather than replacing the file.
	second, err := RenderDropIn(first, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if !strings.Contains(second, "PasswordAuthentication no\n") ||
		!strings.Contains(second, "PermitRootLogin no\n") {
		t.Errorf("the second write lost the first setting:\n%s", second)
	}

	// And setting the same keyword again replaces the line rather than
	// appending a second one sshd would silently ignore.
	third, err := RenderDropIn(second, "PasswordAuthentication", "yes")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if count := strings.Count(third, "PasswordAuthentication"); count != 1 {
		t.Errorf("PasswordAuthentication appears %d times:\n%s", count, third)
	}
	if !strings.Contains(third, "PasswordAuthentication yes\n") {
		t.Errorf("the value was not replaced:\n%s", third)
	}

	// What is written parses back into the same settings: the file the form
	// writes is a file this tool can read.
	settings := parseDropIn(third)
	if len(settings) != 2 {
		t.Fatalf("round trip = %+v, want two settings", settings)
	}

	if _, err := RenderDropIn("", "PermitRootLogin", "maybe"); err == nil {
		t.Errorf("RenderDropIn accepted a value sshd would refuse")
	}
}

// TestRenderMatchDropInKeepsMatchBlocksLast is the rule the whole Match
// renderer exists for: sshd reads everything after a Match line as part of that
// block, so a keyword written at file scope after one would silently apply to
// some connections only. However the two editors are used, and in whatever
// order, the generated file puts every file-scope keyword first.
func TestRenderMatchDropInKeepsMatchBlocksLast(t *testing.T) {
	withMatch, err := RenderMatchDropIn("", MatchUser, "ana",
		"PasswordAuthentication", "no")
	if err != nil {
		t.Fatalf("RenderMatchDropIn: %v", err)
	}
	if !strings.Contains(withMatch, "\nMatch User ana\n") {
		t.Fatalf("the block was not written:\n%s", withMatch)
	}

	// Now a file-scope keyword, written after the block already exists.
	both, err := RenderDropIn(withMatch, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	scope := strings.Index(both, "PermitRootLogin no")
	match := strings.Index(both, "Match User ana")
	if scope < 0 || match < 0 {
		t.Fatalf("the second write lost something:\n%s", both)
	}
	if scope > match {
		t.Errorf("a file-scope keyword was written after a Match block, so sshd "+
			"would read it as part of the block:\n%s", both)
	}

	// A second block joins the first rather than replacing it, and the keyword
	// inside one block does not touch the same keyword at file scope.
	three, err := RenderMatchDropIn(both, MatchAddress, "203.0.113.0/24",
		"PermitRootLogin", "yes")
	if err != nil {
		t.Fatalf("RenderMatchDropIn: %v", err)
	}
	if strings.Count(three, "Match ") != 2 {
		t.Errorf("the file carries %d Match blocks, want 2:\n%s",
			strings.Count(three, "Match "), three)
	}
	if !strings.Contains(three, "\nPermitRootLogin no\n") {
		t.Errorf("the file-scope value was rewritten by a Match block:\n%s", three)
	}
	if strings.Index(three, "Match User ana") > strings.Index(three,
		"Match Address 203.0.113.0/24") {
		t.Errorf("the blocks were reordered:\n%s", three)
	}

	// Setting the same keyword in the same block replaces the line rather than
	// appending a second one sshd would silently ignore.
	again, err := RenderMatchDropIn(three, MatchUser, "ana",
		"PasswordAuthentication", "yes")
	if err != nil {
		t.Fatalf("RenderMatchDropIn: %v", err)
	}
	if count := strings.Count(again, "PasswordAuthentication"); count != 1 {
		t.Errorf("PasswordAuthentication appears %d times:\n%s", count, again)
	}

	// And what was written parses back into the same blocks: the file the form
	// writes is a file this tool can read.
	blocks := parseDropInBlocks(again)
	if len(blocks) != 3 {
		t.Fatalf("round trip = %d blocks, want the file scope and two Match", len(blocks))
	}
	if blocks[1].criteria != "User ana" ||
		blocks[2].criteria != "Address 203.0.113.0/24" {
		t.Errorf("round trip criteria = %q, %q", blocks[1].criteria, blocks[2].criteria)
	}
	if len(blocks[0].settings) != 1 {
		t.Errorf("the file scope round-tripped as %+v", blocks[0].settings)
	}
}

func TestRenderMatchDropInRefusesWhatSshdWould(t *testing.T) {
	// The value goes through exactly the same validator the file-scope editor
	// uses, so the Match form cannot approve something that form would refuse.
	if _, err := RenderMatchDropIn("", MatchUser, "ana",
		"PermitRootLogin", "maybe"); err == nil {
		t.Errorf("RenderMatchDropIn accepted a value sshd would refuse")
	}
	if _, err := RenderMatchDropIn("", MatchUser, "ana",
		"ForceCommand", "/bin/true"); err == nil {
		t.Errorf("RenderMatchDropIn accepted a keyword the editor does not offer")
	}
}

func TestMatchCriteria(t *testing.T) {
	ok := map[string]string{
		MatchUser + " ana":                        "User ana",
		MatchUser + " ana,deploy":                 "User ana,deploy",
		MatchGroup + " wheel":                     "Group wheel",
		MatchAddress + " 203.0.113.7":             "Address 203.0.113.7",
		MatchAddress + " 203.0.113.0/24":          "Address 203.0.113.0/24",
		MatchAddress + " 2001:db8::/32":           "Address 2001:db8::/32",
		MatchAddress + " 10.0.0.0/8,!10.1.0.0/16": "Address 10.0.0.0/8,!10.1.0.0/16",
		// The criteria name is matched the way sshd matches keywords.
		"user ana": "User ana",
	}
	for input, want := range ok {
		parts := strings.SplitN(input, " ", 2)
		got, err := MatchCriteria(parts[0], parts[1])
		if err != nil {
			t.Errorf("MatchCriteria(%q) = %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("MatchCriteria(%q) = %q, want %q", input, got, want)
		}
	}

	bad := [][2]string{
		{MatchUser, ""},
		// A space would end the criteria and start a keyword, and a # would
		// comment the rest of the line out.
		{MatchUser, "ana deploy"},
		{MatchUser, "ana # and"},
		{MatchUser, "ana\nPermitRootLogin yes"},
		// An address that looks fine and selects nothing.
		{MatchAddress, "10.0"},
		{MatchAddress, "203.0.113.0/33"},
		{MatchAddress, "not-an-address"},
		// A criteria sshd has but this form cannot check.
		{"LocalPort", "22"},
		{"", "ana"},
	}
	for _, pair := range bad {
		if got, err := MatchCriteria(pair[0], pair[1]); err == nil {
			t.Errorf("MatchCriteria(%q, %q) accepted it as %q", pair[0], pair[1], got)
		}
	}
}

func TestDiff(t *testing.T) {
	before, err := RenderDropIn("", "PasswordAuthentication", "yes")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	after, err := RenderDropIn(before, "PasswordAuthentication", "no")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}

	diff := Diff(DropInPath, before, after)
	for _, want := range []string{
		"--- " + DropInPath,
		"+++ " + DropInPath,
		"-PasswordAuthentication yes",
		"+PasswordAuthentication no",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff is missing %q:\n%s", want, diff)
		}
	}
	// The unchanged banner is not repeated in the hunk: the dialog has one job,
	// which is to show the line that changed.
	if strings.Contains(diff, "-# Written by tui-ssh") {
		t.Errorf("the diff repeated an unchanged line:\n%s", diff)
	}
}

func TestDiffOnANewFile(t *testing.T) {
	diff := Diff(DropInPath, "", "PermitRootLogin no\n")
	if !strings.Contains(diff, "--- /dev/null") {
		t.Errorf("a new file must diff against /dev/null:\n%s", diff)
	}
	if Diff(DropInPath, "same\n", "same\n") != "" {
		t.Errorf("an identical file must produce no diff")
	}
}

func TestCapabilitiesCoverEveryEditableKey(t *testing.T) {
	// The UI builds its form from the capability set alone, so a keyword the
	// editor offers with no help text and no validator would reach the form as
	// an empty box that refuses everything typed into it.
	caps := Capabilities()
	for _, key := range caps.EditableKeys {
		if caps.Help[key] == "" {
			t.Errorf("%s has no help text", key)
		}
		spec, ok := editable[key]
		if !ok {
			t.Fatalf("%s is offered but has no specification", key)
		}
		if len(spec.choices) == 0 && spec.pattern == nil {
			t.Errorf("%s has neither a value set nor a validator", key)
		}
		if options, closed := caps.ChoicesFor(key); closed {
			for _, option := range options {
				if err := CheckValue(key, option); err != nil {
					t.Errorf("%s offers %q and then refuses it: %v", key, option, err)
				}
			}
		}
	}
}
