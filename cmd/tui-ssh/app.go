package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// screen is one of the five views the tool is made of. They are tabs rather
// than nested screens because they answer five separate questions about the
// same server, and a reader arrives with one of them already in mind.
type screen int

const (
	screenConfig screen = iota
	screenSessions
	screenAuth
	screenHostKeys
	screenService
	screenCount
)

// title names a screen for the tab bar.
func (s screen) title() string {
	switch s {
	case screenSessions:
		return "sessions"
	case screenAuth:
		return "auth log"
	case screenHostKeys:
		return "host keys"
	case screenService:
		return "service"
	default:
		return "config"
	}
}

// mode is the dialog the app currently has open. Only one is open at a time,
// which keeps the update loop flat.
type mode int

const (
	modeBrowse mode = iota
	modeDetail
	modeConfirm
	modeFilter
	modePicker
	modeForm
	modeHelp
)

// app is the tui-ssh Bubble Tea model.
type app struct {
	backend ssh.Backend
	theme   theme.Theme
	caps    ssh.Capabilities
	// backendCompat is what the version probe found, rendered in the header.
	backendCompat compat.Result

	model ssh.Model
	// window is the period the authentication log is read over.
	window string

	// The rows left after the filter, per screen, in display order.
	settings []ssh.Setting
	sessions []ssh.Session
	events   []ssh.AuthEvent
	hostKeys []ssh.HostKey

	width, height int
	screen        screen
	// cursor and offset are per screen, so moving between tabs does not lose
	// the row the reader was on.
	cursor [screenCount]int
	offset [screenCount]int
	filter string

	// detailOffset scrolls the detail screen.
	detailOffset int

	mode    mode
	confirm ui.Confirm
	input   ui.Input
	picker  ui.Picker
	form    settingForm
	// pickerFor names the form field an open picker is filling.
	pickerFor string

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last Load returned an error, so the empty
	// state does not claim the machine simply has no SSH server.
	loadFailed bool
	// busy blocks input while a command runs.
	busy bool
}

// loadedMsg carries the result of a Load.
type loadedMsg struct {
	model ssh.Model
	err   error
}

// authMsg carries the result of re-reading the authentication log.
type authMsg struct {
	log ssh.AuthLog
	err error
}

// ranMsg carries the result of running a plan.
type ranMsg struct {
	// title is the plan's title, echoed in the status line.
	title  string
	output string
	err    error
}

// plan is what a confirm dialog is holding: one or more commands, run in
// order. Most actions are a single command; writing the drop-in is two, and
// replacing the host keys is four, and all of them are shown before any runs.
type plan struct {
	title    string
	commands []ssh.Command
}

// newApp builds the model around a backend.
func newApp(backend ssh.Backend, th theme.Theme,
	backendCompat compat.Result) *app {
	a := &app{
		backend:       backend,
		theme:         th,
		caps:          backend.Capabilities(),
		backendCompat: backendCompat,
		window:        ssh.Window24h,
		width:         80,
		height:        24,
		loading:       true,
	}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first load.
func (a *app) Init() tea.Cmd { return a.load() }

// load reads the server's state in the background.
func (a *app) load() tea.Cmd {
	backend, window := a.backend, a.window
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		model, err := backend.Load(ctx, window)
		return loadedMsg{model: model, err: err}
	}
}

// loadAuth re-reads only the authentication log, which is what switching the
// window does. It is its own command because a week of journal is the slowest
// read the tool makes and there is no reason to repeat the other four.
func (a *app) loadAuth() tea.Cmd {
	backend, model, window := a.backend, a.model, a.window
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		log, err := backend.LoadAuth(ctx, model, window)
		return authMsg{log: log, err: err}
	}
}

// run executes a confirmed plan in the background, one command at a time,
// stopping at the first failure.
func (a *app) run(p plan) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var outputs []string
		for _, cmd := range p.commands {
			out, err := backend.Run(ctx, cmd)
			if err != nil {
				return ranMsg{title: p.title, output: out, err: err}
			}
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		return ranMsg{title: p.title, output: strings.Join(outputs, "; ")}
	}
}

// setStatus records a plain message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.model = msg.model
		a.applyFilter()
		return a, nil

	case authMsg:
		a.loading = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.model.Auth = msg.log
		a.applyFilter()
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.load()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.title, firstLine(summary))
		a.loading = true
		return a, a.load()

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeFilter {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	if a.mode == modeForm {
		return a, a.form.updateActive(msg)
	}
	return a, nil
}

// handleKey routes a key press to the open dialog, or to the current screen.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeFilter:
		return a.handleFilter(msg)
	case modePicker:
		return a.handlePicker(msg)
	case modeForm:
		return a.handleForm(msg)
	case modeHelp:
		a.mode = modeBrowse
		return a, nil
	case modeDetail:
		return a.handleDetailKey(msg)
	default:
		return a.handleBrowseKey(msg)
	}
}

// handleConfirm resolves the confirm dialog.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = modeBrowse
	confirmed := a.confirm.Confirmed
	pending, ok := a.confirm.Payload.(plan)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(pending.commands[0]))
	return a, a.run(pending)
}

// handleFilter resolves the filter prompt.
func (a *app) handleFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		// Filter as the user types.
		a.filter = a.input.Value()
		a.applyFilter()
		return a, cmd
	}
	if a.input.Accepted {
		a.filter = a.input.Value()
	} else {
		a.filter = ""
	}
	a.applyFilter()
	a.mode = modeBrowse
	return a, nil
}

// handlePicker resolves the open picker, which serves the form's two fields.
func (a *app) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.picker.Update(msg)
	if !a.picker.Done {
		return a, nil
	}
	choice, accepted := a.picker.Selected(), a.picker.Accepted
	field := a.pickerFor
	a.picker, a.pickerFor = ui.Picker{}, ""
	if accepted {
		a.form.set(field, choice, a.model, a.caps)
	}
	a.mode = modeForm
	return a, nil
}

// handleForm routes keys to the setting editor.
func (a *app) handleForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.mode = modeBrowse
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	case "tab", "down":
		a.form.next()
		return a, nil
	case "shift+tab", "up":
		a.form.prev()
		return a, nil
	case "left":
		if a.form.activeIsChoice() {
			a.form.cycle(-1, a.model, a.caps)
			return a, nil
		}
	case "right":
		if a.form.activeIsChoice() {
			a.form.cycle(1, a.model, a.caps)
			return a, nil
		}
	case " ":
		// Space opens the list for a choice field. It is not enter, because
		// enter has to mean "apply" from every field — the value field of a
		// keyword like PermitRootLogin is a choice, and a form whose only
		// choice fields could never submit would be a dead end.
		if a.form.activeIsChoice() {
			a.pickerFor = a.form.activeKey()
			a.picker = ui.NewPicker(a.form.activeLabel(),
				a.form.activeOptions(), a.form.activeValue())
			a.mode = modePicker
			return a, nil
		}
	case "enter":
		return a, a.submitForm()
	}
	return a, a.form.updateActive(msg)
}

// submitForm renders the drop-in, has sshd check it, diffs it against what is
// on disk and opens the confirm dialog with the check, the diff and the
// commands that apply it.
func (a *app) submitForm() tea.Cmd {
	write, err := a.backend.BuildSetOption(a.model, a.form.key(), a.form.value())
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	title := "Set " + a.form.key() + " to " + a.form.value()
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    a.writeBody(write),
		Command: a.previewAll(write.Commands),
		Danger:  true,
		Payload: plan{title: title, commands: write.Commands},
	}
	return nil
}

// writeBody is what the confirm dialog says above the commands: whether sshd
// accepted the staged file, the caveat that applies to this change, and the
// diff itself.
func (a *app) writeBody(write ssh.WritePlan) string {
	var parts []string
	if write.Validated {
		parts = append(parts, "✓ "+write.Validation)
	} else if write.Validation != "" {
		parts = append(parts, "! the syntax check "+write.Validation)
	}
	if write.Warning != "" {
		parts = append(parts, write.Warning)
	}
	parts = append(parts, a.diffForDialog(write.Diff))
	return strings.Join(parts, "\n\n")
}

// previewAll renders every command of a plan, one per line, each with the
// prompt the dialog puts in front of the first one.
func (a *app) previewAll(commands []ssh.Command) string {
	previews := make([]string, 0, len(commands))
	for _, cmd := range commands {
		previews = append(previews, a.backend.Preview(cmd))
	}
	return strings.Join(previews, "\n$ ")
}

// handleBrowseKey handles a screen's own keys.
func (a *app) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.cursor[a.screen], a.offset[a.screen] = 0, 0
	case "G", "end":
		a.cursor[a.screen] = max(a.rowCount()-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "tab", "l", "right":
		a.gotoScreen((a.screen + 1) % screenCount)
	case "shift+tab", "h", "left":
		a.gotoScreen((a.screen + screenCount - 1) % screenCount)
	case "1", "2", "3", "4", "5":
		a.gotoScreen(screen(msg.String()[0] - '1'))
	case "/":
		a.input = ui.NewInput("Filter "+a.screen.title(), "any column…", a.filter)
		a.input.Help = "Matches any column of this screen. Empty clears the filter."
		a.mode = modeFilter
	case "enter":
		if a.rowCount() == 0 {
			a.setStatus(ui.StatusWarn, "nothing selected")
			return a, nil
		}
		a.mode, a.detailOffset = modeDetail, 0
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleActionKey(msg)
	}
	return a, nil
}

// handleDetailKey handles the per-row screen. The action keys are the same
// ones the table offers, applied to the row on screen.
func (a *app) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "left":
		a.mode, a.detailOffset = modeBrowse, 0
		return a, nil
	case "?":
		a.mode = modeHelp
		return a, nil
	case "j", "down":
		a.detailOffset++
		return a, nil
	case "k", "up":
		a.detailOffset = max(a.detailOffset-1, 0)
		return a, nil
	case "g", "home":
		a.detailOffset = 0
		return a, nil
	case "pgdown", "ctrl+f":
		a.detailOffset += a.detailHeight()
		return a, nil
	case "pgup", "ctrl+b":
		a.detailOffset = max(a.detailOffset-a.detailHeight(), 0)
		return a, nil
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleActionKey(msg)
	}
}

// handleActionKey handles the keys that mean the same thing on every screen.
func (a *app) handleActionKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "e":
		return a.openForm()
	case "t":
		return a.confirmTerminate()
	case "b":
		return a.confirmDeny()
	case "K":
		return a.confirmRegenerate()
	case "r":
		return a.buildAndConfirm("Reload the SSH service", func() (ssh.Command, error) {
			return a.backend.BuildReload(a.model)
		})
	case "w":
		return a.toggleWindow()
	}
	return nil
}

// toggleWindow switches the authentication log between a day and a week.
func (a *app) toggleWindow() tea.Cmd {
	if a.window == ssh.Window24h {
		a.window = ssh.Window7d
	} else {
		a.window = ssh.Window24h
	}
	a.screen = screenAuth
	a.loading = true
	a.setStatusf(ui.StatusInfo, "reading the last %s…", a.window)
	return a.loadAuth()
}

// openForm opens the guided editor, seeded from the selected setting when the
// config screen is what is on show.
func (a *app) openForm() tea.Cmd {
	if !a.caps.SupportsEdit {
		a.setStatus(ui.StatusWarn, "this backend has no configuration to edit")
		return nil
	}
	if len(a.caps.EditableKeys) == 0 {
		a.setStatus(ui.StatusWarn, "this backend offers no editable settings")
		return nil
	}
	key := a.caps.EditableKeys[0]
	if setting, ok := a.selectedSetting(); ok && a.editable(setting.Key) {
		key = setting.Key
	}
	a.form = newSettingForm(key, a.model, a.caps)
	a.mode = modeForm
	return nil
}

// editable reports whether a keyword is one the guided editor offers.
func (a *app) editable(key string) bool {
	for _, candidate := range a.caps.EditableKeys {
		if strings.EqualFold(candidate, key) {
			return true
		}
	}
	return false
}

// confirmTerminate asks before ending a session.
func (a *app) confirmTerminate() tea.Cmd {
	if !a.caps.SupportsTerminate {
		a.setStatus(ui.StatusWarn, "this backend cannot end a session")
		return nil
	}
	session, ok := a.selectedSession()
	if !ok {
		a.setStatus(ui.StatusWarn, "no session selected — press 2 for the sessions screen")
		return nil
	}
	cmd, err := a.backend.BuildTerminateSession(session)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.openConfirm(cmd.Description, cmd.Description+
		".\nEverything running in it is killed, and if this is your own session "+
		"you will lose it.", cmd)
	return nil
}

// confirmDeny asks before blocking an address at the firewall.
func (a *app) confirmDeny() tea.Cmd {
	ip, ok := a.selectedIP()
	if !ok {
		a.setStatus(ui.StatusWarn,
			"no address selected — press 3 for the auth log, or 2 for the sessions")
		return nil
	}
	cmd, err := a.backend.BuildDenyIP(a.model, ip)
	if err != nil {
		// No firewall this tool drives: the address is still worth naming, and
		// the tool that owns the firewall is worth naming too.
		a.setStatus(ui.StatusWarn, err.Error())
		return nil
	}
	a.openConfirm("Block "+ip, cmd.Description+
		".\nThis writes a firewall rule, not an sshd setting; tui-firewall is "+
		"where it can be reviewed and removed.", cmd)
	return nil
}

// confirmRegenerate asks before replacing the server's host keys.
func (a *app) confirmRegenerate() tea.Cmd {
	if !a.caps.SupportsRegenerateHostKeys {
		a.setStatus(ui.StatusWarn, "this backend cannot replace the host keys")
		return nil
	}
	commands, err := a.backend.BuildRegenerateHostKeys(a.model)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	title := "Regenerate the host keys"
	a.confirm = ui.Confirm{
		Title: title,
		Body: "This changes the server's identity. Every client that has " +
			"connected before will refuse to connect and print the big " +
			"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED banner until its " +
			"known_hosts entry is removed.\n\nThe current keys are moved aside, " +
			"not deleted, so this is reversible with a mv you can read.",
		Command: a.previewAll(commands),
		Danger:  true,
		Payload: plan{title: title, commands: commands},
	}
	return nil
}

// buildAndConfirm runs a command builder and opens the confirm dialog, or
// reports the builder's error in the status line.
func (a *app) buildAndConfirm(title string,
	build func() (ssh.Command, error)) tea.Cmd {
	cmd, err := build()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.openConfirm(title, cmd.Description+".", cmd)
	return nil
}

// openConfirm shows one command and what it does.
func (a *app) openConfirm(title, body string, cmd ssh.Command) {
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    body,
		Command: a.backend.Preview(cmd),
		Danger:  cmd.Destructive,
		Payload: plan{title: title, commands: []ssh.Command{cmd}},
	}
}

// gotoScreen switches tabs, keeping the filter applied.
func (a *app) gotoScreen(next screen) {
	if next < 0 || next >= screenCount {
		return
	}
	a.screen = next
	a.clampCursor()
}

// applyFilter recomputes every screen's visible rows from the current filter.
func (a *app) applyFilter() {
	needle := strings.ToLower(a.filter)
	keep := func(haystack string) bool {
		return needle == "" || strings.Contains(strings.ToLower(haystack), needle)
	}

	a.settings = nil
	for _, setting := range a.model.Settings {
		if keep(settingHaystack(setting)) {
			a.settings = append(a.settings, setting)
		}
	}
	a.sessions = nil
	for _, session := range a.model.Sessions {
		if keep(sessionHaystack(session)) {
			a.sessions = append(a.sessions, session)
		}
	}
	a.events = nil
	for _, event := range a.model.Auth.Events {
		if keep(event.Raw) {
			a.events = append(a.events, event)
		}
	}
	a.hostKeys = nil
	for _, key := range a.model.HostKeys {
		if keep(key.Type + " " + key.Fingerprint + " " + key.Path + " " + key.Comment) {
			a.hostKeys = append(a.hostKeys, key)
		}
	}
	a.clampCursor()
}

// settingHaystack is the text the filter matches a setting against.
func settingHaystack(s ssh.Setting) string {
	parts := []string{s.Key, s.Value, string(s.Verdict), s.Note}
	for _, source := range s.Sources {
		parts = append(parts, source.String(), source.Text)
	}
	return strings.Join(parts, " ")
}

// sessionHaystack is the text the filter matches a session against.
func sessionHaystack(s ssh.Session) string {
	return strings.Join([]string{s.ID, s.User, s.RemoteIP, s.TTY, s.Since, s.State}, " ")
}

// rowCount is how many rows the current screen has after the filter.
func (a *app) rowCount() int {
	switch a.screen {
	case screenSessions:
		return len(a.sessions)
	case screenAuth:
		return len(a.events)
	case screenHostKeys:
		return len(a.hostKeys)
	case screenService:
		return len(a.serviceRows())
	default:
		return len(a.settings)
	}
}

// selectedSetting is the highlighted row of the config screen.
func (a *app) selectedSetting() (ssh.Setting, bool) {
	if a.screen != screenConfig {
		return ssh.Setting{}, false
	}
	index := a.cursor[screenConfig]
	if index < 0 || index >= len(a.settings) {
		return ssh.Setting{}, false
	}
	return a.settings[index], true
}

// selectedSession is the highlighted row of the sessions screen.
func (a *app) selectedSession() (ssh.Session, bool) {
	if a.screen != screenSessions {
		return ssh.Session{}, false
	}
	index := a.cursor[screenSessions]
	if index < 0 || index >= len(a.sessions) {
		return ssh.Session{}, false
	}
	return a.sessions[index], true
}

// selectedEvent is the highlighted row of the auth log screen.
func (a *app) selectedEvent() (ssh.AuthEvent, bool) {
	if a.screen != screenAuth {
		return ssh.AuthEvent{}, false
	}
	index := a.cursor[screenAuth]
	if index < 0 || index >= len(a.events) {
		return ssh.AuthEvent{}, false
	}
	return a.events[index], true
}

// selectedHostKey is the highlighted row of the host keys screen.
func (a *app) selectedHostKey() (ssh.HostKey, bool) {
	if a.screen != screenHostKeys {
		return ssh.HostKey{}, false
	}
	index := a.cursor[screenHostKeys]
	if index < 0 || index >= len(a.hostKeys) {
		return ssh.HostKey{}, false
	}
	return a.hostKeys[index], true
}

// selectedIP is the address the block action applies to: the one the
// highlighted log line came from, or the one the highlighted session is on.
func (a *app) selectedIP() (string, bool) {
	if event, ok := a.selectedEvent(); ok && event.IP != "" {
		return event.IP, true
	}
	if session, ok := a.selectedSession(); ok && session.RemoteIP != "" {
		return session.RemoteIP, true
	}
	return "", false
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.cursor[a.screen] += delta
	a.clampCursor()
}

// clampCursor keeps the cursor and the scroll offset of every screen in range.
func (a *app) clampCursor() {
	for s := screen(0); s < screenCount; s++ {
		count := a.countFor(s)
		if count == 0 {
			a.cursor[s], a.offset[s] = 0, 0
			continue
		}
		a.cursor[s] = min(max(a.cursor[s], 0), count-1)

		height := a.tableHeight()
		if a.cursor[s] < a.offset[s] {
			a.offset[s] = a.cursor[s]
		}
		if a.cursor[s] >= a.offset[s]+height {
			a.offset[s] = a.cursor[s] - height + 1
		}
		a.offset[s] = max(min(a.offset[s], max(count-height, 0)), 0)
	}
}

// countFor is rowCount for a screen that is not the current one.
func (a *app) countFor(s screen) int {
	current := a.screen
	a.screen = s
	count := a.rowCount()
	a.screen = current
	return count
}

// firstLine keeps status messages to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
