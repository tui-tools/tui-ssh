package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-ssh/internal/openssh"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// newTestApp builds an app on the sample server, sized like a normal terminal
// and already loaded.
func newTestApp(t *testing.T) (*app, *openssh.Fake) {
	t.Helper()
	backend := openssh.NewFake()
	a := newApp(backend, theme.New(), compat.Result{})
	a.width, a.height = 100, 30
	drain(t, a, a.Init())
	return a, backend
}

// drain runs a tea.Cmd and feeds its message back into the model, which is
// what the Bubble Tea runtime does. It is how a test exercises a load.
func drain(t *testing.T, a *app, cmd tea.Cmd) {
	t.Helper()
	for range 4 {
		if cmd == nil {
			return
		}
		msg := cmd()
		if msg == nil {
			return
		}
		_, cmd = a.Update(msg)
	}
}

// press sends one key and returns the command it produced.
func press(a *app, key string) tea.Cmd {
	var msg tea.KeyMsg
	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
	_, cmd := a.Update(msg)
	return cmd
}

// gotoScreen moves to a tab by its number key.
func gotoScreen(t *testing.T, a *app, s screen) {
	t.Helper()
	drain(t, a, press(a, string(rune('1'+int(s))))) //nolint:gosec // s is one of the few screen constants, so the digit key is always a single rune
	if a.screen != s {
		t.Fatalf("did not reach the %s screen", s.title())
	}
}

// selectSetting moves the cursor to a keyword by name.
func selectSetting(t *testing.T, a *app, key string) {
	t.Helper()
	gotoScreen(t, a, screenConfig)
	for i, setting := range a.settings {
		if strings.EqualFold(setting.Key, key) {
			a.cursor[screenConfig] = i
			return
		}
	}
	t.Fatalf("no setting named %q on the sample server", key)
}

func TestLoadsTheSampleServer(t *testing.T) {
	a, _ := newTestApp(t)
	if len(a.settings) == 0 {
		t.Fatalf("no settings were loaded")
	}
	if len(a.sessions) != 2 || len(a.hostKeys) != 3 {
		t.Errorf("sessions = %d, host keys = %d; want 2 and 3",
			len(a.sessions), len(a.hostKeys))
	}
	if a.model.Auth.Failed != 37 {
		t.Errorf("failed logins = %d, want 37", a.model.Auth.Failed)
	}
	if len(a.model.Auth.TopIPs) != 3 {
		t.Errorf("the failures came from %d addresses, want 3",
			len(a.model.Auth.TopIPs))
	}
	// The first row is the question a reader arrives with.
	if a.settings[0].Key != "PermitRootLogin" {
		t.Errorf("first row = %q", a.settings[0].Key)
	}
	if !strings.Contains(a.View(), "PasswordAuthentication") {
		t.Errorf("the settings table is missing from the first frame")
	}
}

// TestActionsPreviewExactlyWhatTheyRun is the family's central promise, as a
// test: for every action key, the command line in the confirm dialog is the
// command line the backend is then asked to run.
func TestActionsPreviewExactlyWhatTheyRun(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		setup func(*testing.T, *app)
		want  string
	}{
		{
			name:  "reload",
			key:   "r",
			setup: func(t *testing.T, a *app) { gotoScreen(t, a, screenConfig) },
			want:  "sudo -n systemctl reload sshd",
		},
		{
			name: "terminate a session",
			key:  "t",
			setup: func(t *testing.T, a *app) {
				gotoScreen(t, a, screenSessions)
			},
			want: "sudo -n loginctl terminate-session 12",
		},
		{
			name: "block an address",
			key:  "b",
			setup: func(t *testing.T, a *app) {
				gotoScreen(t, a, screenAuth)
				a.cursor[screenAuth] = 0
			},
			want: "sudo -n ufw deny from 192.0.2.10",
		},
	}
	for _, test := range tests {
		a, backend := newTestApp(t)
		test.setup(t, a)

		drain(t, a, press(a, test.key))
		if a.mode != modeConfirm {
			t.Fatalf("%s: no confirm dialog opened (status: %s)", test.name, a.status)
		}
		if a.confirm.Command != test.want {
			t.Errorf("%s: previewed %q, want %q", test.name, a.confirm.Command, test.want)
		}

		drain(t, a, press(a, "y"))
		ran := backend.Ran()
		if len(ran) != 1 {
			t.Fatalf("%s: ran %d commands, want 1", test.name, len(ran))
		}
		if got := backend.Preview(ran[0]); got != test.want {
			t.Errorf("%s: ran %q, want the previewed %q", test.name, got, test.want)
		}
	}
}

func TestCancellingRunsNothing(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenSessions)
	drain(t, a, press(a, "t"))
	drain(t, a, press(a, "n"))

	if len(backend.Ran()) != 0 {
		t.Errorf("answering no ran %d commands", len(backend.Ran()))
	}
	if a.status != "cancelled" {
		t.Errorf("status = %q, want cancelled", a.status)
	}
}

// TestEditingWritesADropInWithADiffAndTwoCommands covers the action the whole
// tool is built around: the file is checked by sshd, diffed, and then installed
// and reloaded, and all of it is on screen before either command runs.
func TestEditingWritesADropInWithADiffAndTwoCommands(t *testing.T) {
	a, backend := newTestApp(t)
	selectSetting(t, a, "PasswordAuthentication")

	drain(t, a, press(a, "e"))
	if a.mode != modeForm {
		t.Fatalf("e did not open the editor (status: %s)", a.status)
	}
	if a.form.key() != "PasswordAuthentication" {
		t.Fatalf("the form opened on %q, want the selected setting", a.form.key())
	}

	// The value field is a picker for this keyword: move to it and pick `no`.
	drain(t, a, press(a, "tab"))
	a.form.set(fieldValue, "no", a.model, a.caps)
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("the form did not open a confirm dialog (status: %s)", a.status)
	}
	if !strings.Contains(a.confirm.Body, "+PasswordAuthentication no") {
		t.Errorf("the confirm dialog does not show the change:\n%s", a.confirm.Body)
	}
	// The syntax check ran before the question was asked, and said so.
	if !strings.Contains(a.confirm.Body, "sshd -t -f") {
		t.Errorf("the dialog does not report the syntax check:\n%s", a.confirm.Body)
	}

	lines := strings.Split(a.confirm.Command, "\n")
	if len(lines) != 2 {
		t.Fatalf("previewed %d command lines, want 2:\n%s",
			len(lines), a.confirm.Command)
	}
	if !strings.Contains(lines[0], "install -m 600") ||
		!strings.Contains(lines[0], openssh.DropInPath) ||
		!strings.Contains(lines[1], "systemctl reload sshd") {
		t.Errorf("previewed commands = %q", a.confirm.Command)
	}

	drain(t, a, press(a, "y"))
	ran := backend.Ran()
	if len(ran) != 2 {
		t.Fatalf("ran %d commands, want the install and the reload", len(ran))
	}
	if ran[0].Argv[0] != "install" || ran[1].String() != "systemctl reload sshd" {
		t.Errorf("ran %v", ran)
	}

	// And the change is what the server now reports.
	if setting, ok := a.model.Setting("PasswordAuthentication"); !ok ||
		setting.Value != "no" {
		t.Errorf("after the write the server still reports %+v", setting)
	}
}

// TestSshdConfigIsNeverWritten is the rule that keeps a hand-written
// configuration safe: there is exactly one file this tool installs, and no key
// sequence produces a command that touches any other.
func TestSshdConfigIsNeverWritten(t *testing.T) {
	a, backend := newTestApp(t)
	selectSetting(t, a, "PermitRootLogin")
	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.set(fieldValue, "no", a.model, a.caps)
	drain(t, a, press(a, "enter"))
	drain(t, a, press(a, "y"))

	for _, cmd := range backend.Ran() {
		line := cmd.String()
		if strings.Contains(line, openssh.ConfigPath) &&
			!strings.Contains(line, openssh.DropInPath) {
			t.Errorf("a command touched %s: %q", openssh.ConfigPath, line)
		}
	}
}

// TestWritingTheSameValueTwiceIsRefused: the second write has nothing to say,
// and installing a byte-identical file plus a reload is not nothing — it drops
// and re-execs the server for no reason.
func TestWritingTheSameValueTwiceIsRefused(t *testing.T) {
	a, backend := newTestApp(t)
	selectSetting(t, a, "PasswordAuthentication")

	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.set(fieldValue, "no", a.model, a.caps)
	drain(t, a, press(a, "enter"))
	drain(t, a, press(a, "y"))
	if len(backend.Ran()) != 2 {
		t.Fatalf("the first write ran %d commands", len(backend.Ran()))
	}

	selectSetting(t, a, "PasswordAuthentication")
	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.set(fieldValue, "no", a.model, a.caps)
	drain(t, a, press(a, "enter"))
	if a.mode == modeConfirm {
		t.Errorf("a no-op write opened a confirm dialog")
	}
	if !strings.Contains(a.status, "already says") {
		t.Errorf("status = %q", a.status)
	}
	if len(backend.Ran()) != 2 {
		t.Errorf("a no-op write ran a command")
	}
}

// TestChangingThePortWarnsAboutTheFirewall: moving where the server accepts
// connections is the one change that can lock the user out of the machine
// through no fault of sshd's.
func TestChangingThePortWarnsAboutTheFirewall(t *testing.T) {
	a, _ := newTestApp(t)
	selectSetting(t, a, "Port")
	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.input.SetValue("2222")
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("the port change did not reach a confirm dialog (status: %s)",
			a.status)
	}
	body := a.confirm.Body
	if !strings.Contains(body, "firewall") || !strings.Contains(body, "tui-firewall") {
		t.Errorf("the dialog does not warn about the firewall:\n%s", body)
	}
}

// TestRegeneratingHostKeysIsLoudAndReversible: the plan moves the old keys
// aside rather than deleting them, and the dialog says what it does to every
// client that has ever connected.
func TestRegeneratingHostKeysIsLoudAndReversible(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenHostKeys)
	drain(t, a, press(a, "K"))

	if a.mode != modeConfirm {
		t.Fatalf("K did not open a confirm dialog (status: %s)", a.status)
	}
	if !strings.Contains(a.confirm.Body, "known_hosts") {
		t.Errorf("the dialog does not warn about known_hosts:\n%s", a.confirm.Body)
	}
	if !a.confirm.Danger {
		t.Errorf("replacing the host keys must be painted as dangerous")
	}
	previews := strings.Split(a.confirm.Command, "\n")
	if len(previews) != 4 {
		t.Fatalf("previewed %d commands, want 4:\n%s", len(previews), a.confirm.Command)
	}

	drain(t, a, press(a, "y"))
	for _, cmd := range backend.Ran() {
		if cmd.Argv[0] == "rm" {
			t.Errorf("the plan deleted a key: %q", cmd.String())
		}
	}
	// The sample server now serves different keys, the way a real one would.
	if a.model.HostKeys[0].Fingerprint ==
		"SHA256:9Uf1YB0mAqxQnzTQ2pO0y1z8cH8h0m3nV5R2fLpKq0E" {
		t.Errorf("the host keys did not change")
	}
}

// TestBlockingWithoutAFirewallIsAHintNotADialog: writing a ufw rule on a
// machine whose firewall is something else looks like it worked, so it is
// refused and the refusal names the tool that owns the real one.
func TestBlockingWithoutAFirewallIsAHintNotADialog(t *testing.T) {
	backend := openssh.NewFake()
	a := newApp(backend, theme.New(), compat.Result{})
	a.width, a.height = 100, 30
	drain(t, a, a.Init())
	a.model.Firewall = ""

	gotoScreen(t, a, screenAuth)
	drain(t, a, press(a, "b"))
	if a.mode == modeConfirm {
		t.Fatalf("a dialog opened for a firewall that is not running")
	}
	if !strings.Contains(a.status, "tui-firewall") {
		t.Errorf("status = %q, want it to point at tui-firewall", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("a command ran anyway")
	}
}

func TestWindowSwitchesTheAuthLog(t *testing.T) {
	a, _ := newTestApp(t)
	if a.window != ssh.Window24h {
		t.Fatalf("window = %q, want the day", a.window)
	}
	drain(t, a, press(a, "w"))
	if a.window != ssh.Window7d || a.screen != screenAuth {
		t.Errorf("w did not switch to the week on the auth screen: %q, %v",
			a.window, a.screen)
	}
	if a.model.Auth.Window != ssh.Window7d {
		t.Errorf("the log was not re-read: %q", a.model.Auth.Window)
	}
	drain(t, a, press(a, "w"))
	if a.window != ssh.Window24h {
		t.Errorf("w did not switch back")
	}
}

func TestFilterMatchesEveryScreen(t *testing.T) {
	a, _ := newTestApp(t)
	a.filter = "PermitEmptyPasswords"
	a.applyFilter()
	if len(a.settings) != 1 {
		t.Errorf("the settings filter matched %d rows, want 1", len(a.settings))
	}

	a.filter = "203.0.113.42"
	a.applyFilter()
	if len(a.sessions) != 1 {
		t.Errorf("the sessions filter matched %d rows, want 1", len(a.sessions))
	}

	a.filter = "ED25519"
	a.applyFilter()
	if len(a.hostKeys) != 1 {
		t.Errorf("the host key filter matched %d rows, want 1", len(a.hostKeys))
	}

	a.filter = "nothing here"
	a.applyFilter()
	if len(a.settings)+len(a.sessions)+len(a.events)+len(a.hostKeys) != 0 {
		t.Errorf("a filter that matches nothing kept rows")
	}
}

// TestEveryScreenHasADetail: enter must open something on all five, because a
// row a reader cannot open is a row whose truncated cells are all they get.
func TestEveryScreenHasADetail(t *testing.T) {
	for s := screen(0); s < screenCount; s++ {
		a, _ := newTestApp(t)
		gotoScreen(t, a, s)
		drain(t, a, press(a, "enter"))
		if a.mode != modeDetail {
			t.Fatalf("%s: enter opened nothing (status: %s)", s.title(), a.status)
		}
		lines := a.detailLines()
		if len(lines) < 3 {
			t.Errorf("%s: the detail screen is %d lines", s.title(), len(lines))
		}
		drain(t, a, press(a, "esc"))
		if a.mode != modeBrowse {
			t.Errorf("%s: esc did not return to the table", s.title())
		}
	}
}

// TestSettingDetailNamesTheWinner is the thing the source column is short for:
// which file decided this value, and what else tried to.
func TestSettingDetailNamesTheWinner(t *testing.T) {
	a, _ := newTestApp(t)
	selectSetting(t, a, "PasswordAuthentication")
	drain(t, a, press(a, "enter"))

	view := strings.Join(a.detailLines(), "\n")
	for _, want := range []string{
		"PasswordAuthentication",
		"wins",
		openssh.ConfigPath,
		"sshd -T",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the detail screen is missing %q:\n%s", want, view)
		}
	}
}

// TestRendersAtEveryWidth is the responsive contract: from a narrow pane to a
// wide screen, no frame may wrap, because a wrapped row desynchronises Bubble
// Tea's line accounting and every frame after it lands in the wrong place.
func TestRendersAtEveryWidth(t *testing.T) {
	for width := 40; width <= 200; width += 4 {
		a, _ := newTestApp(t)
		a.width, a.height = width, 24
		a.clampCursor()

		for s := screen(0); s < screenCount; s++ {
			a.screen = s
			for _, m := range []mode{modeBrowse, modeDetail} {
				a.mode = m
				checkWidth(t, a, s.title(), width)
			}
		}

		a.mode = modeHelp
		checkWidth(t, a, "help", width)

		a.mode = modeForm
		a.form = newSettingForm("PermitRootLogin", a.model, a.caps)
		checkWidth(t, a, "form", width)
	}
}

// checkWidth renders the current frame and fails when a line overflows.
func checkWidth(t *testing.T, a *app, name string, width int) {
	t.Helper()
	for i, line := range strings.Split(a.View(), "\n") {
		if got := lineWidth(line); got > width {
			t.Fatalf("%s at %d cols: line %d is %d cells wide",
				name, width, i, got)
		}
	}
}

// lineWidth measures a rendered line, ignoring the ANSI escapes the theme adds.
func lineWidth(line string) int {
	width, inEscape := 0, false
	for _, r := range line {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && (r == 'm' || r == 'K' || r == 'H'):
			inEscape = false
		case inEscape:
		default:
			width++
		}
	}
	return width
}

func TestBusyStateSwallowsInput(t *testing.T) {
	a, backend := newTestApp(t)
	gotoScreen(t, a, screenSessions)
	a.busy = true
	drain(t, a, press(a, "t"))
	if a.mode != modeBrowse || len(backend.Ran()) != 0 {
		t.Errorf("a key pressed while a command runs must be ignored")
	}
}

// TestEditorRefusesAValueSshdWouldNot: the form and the file renderer share
// one validator, so the form cannot approve something the renderer refuses.
func TestEditorRefusesAValueSshdWouldNot(t *testing.T) {
	a, backend := newTestApp(t)
	selectSetting(t, a, "MaxAuthTries")
	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.input.SetValue("three")
	drain(t, a, press(a, "enter"))

	if a.mode == modeConfirm {
		t.Errorf("the form accepted a value sshd would refuse")
	}
	if a.status == "" {
		t.Errorf("the form refused silently")
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("a command ran anyway")
	}
}
