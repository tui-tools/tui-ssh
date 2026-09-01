package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// Layout constants: the rows the table cannot use.
const (
	headerLines = 2
	footerLines = 2
	// tabLines is the one row the tab bar takes.
	tabLines = 1
	// minTableHeight keeps at least one visible row on a very short terminal.
	minTableHeight = 1
)

// tableHeight is the number of rows that fit on screen.
func (a *app) tableHeight() int {
	// header + tabs + table header + footer + status line.
	return max(a.height-headerLines-tabLines-footerLines-2, minTableHeight)
}

// detailHeight is the number of detail lines that fit on screen.
func (a *app) detailHeight() int {
	return max(a.height-headerLines-tabLines-footerLines-1, minTableHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeFilter, modePrompt:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeForm:
		return a.form.view(a.theme, a.width, a.height)
	case modeHelp:
		return placeCenter(
			ui.HelpScreen(a.theme, "tui-ssh — keys", helpKeys(), a.width),
			a.width, a.height)
	case modeDetail:
		return a.detailView()
	}
	return a.browseView()
}

// placeCenter centers a rendered box in the terminal.
func placeCenter(box string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// browseView renders a screen: header, tab bar, table, help bar, status.
func (a *app) browseView() string {
	header := a.headerView()
	tabs := a.tabsView()

	var body string
	switch {
	case a.loading && a.rowCount() == 0:
		body = ui.EmptyState(a.theme, "reading the server…", a.width, a.tableHeight()+1)
	case a.rowCount() == 0 && a.filter != "":
		body = ui.EmptyState(a.theme, "nothing matches "+strconv.Quote(a.filter),
			a.width, a.tableHeight()+1)
	case a.rowCount() == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme,
			"could not read the server — see the message below",
			a.width, a.tableHeight()+1)
	case a.rowCount() == 0:
		body = ui.EmptyState(a.theme, a.emptyMessage(), a.width, a.tableHeight()+1)
	default:
		body = a.table()
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{header, tabs, body, help, status}, "\n")
}

// emptyMessage is what a screen with no rows says, which is different on each.
func (a *app) emptyMessage() string {
	switch a.screen {
	case screenSessions:
		return "nobody is logged in over SSH right now"
	case screenAuth:
		if a.model.Auth.Unavailable != "" {
			return a.model.Auth.Unavailable
		}
		return "no authentication attempt in the last " + a.model.Auth.Window
	case screenHostKeys:
		return "no host key was found in /etc/ssh"
	case screenService:
		return "the SSH service could not be read"
	case screenUsers:
		return "no local account could be read from /etc/passwd"
	default:
		return a.noSettingsMessage()
	}
}

// noSettingsMessage explains an empty configuration screen, which is not the
// same failure everywhere.
//
// On a stock Fedora or Arch machine, run as a plain user whose sudo asks for a
// password, both reads fail at once: `sshd -T` needs root, and sshd_config is
// mode 0600 so even reading the file back is refused. The screen that results
// is empty for a reason the user can act on, and saying "no settings" instead
// of naming that reason would send them looking for a bug in the tool.
func (a *app) noSettingsMessage() string {
	if a.model.EffectiveReason == "" {
		return "this server reports no configuration at all"
	}
	for _, file := range a.model.Files {
		if file.Unreadable == "" {
			continue
		}
		return "neither sshd nor " + file.Path + " could be read — " +
			"re-run with sudo, or as root"
	}
	return "sshd itself could not be asked: " + a.model.EffectiveReason
}

// headerView renders the facts at the top of every screen.
func (a *app) headerView() string {
	t := a.theme

	unitValue, unitStyle := a.model.Service.Unit+" running", t.OK
	if !a.model.Service.Active {
		unitValue = a.model.Service.Unit + " " + orNone(a.model.Service.ActiveState)
		unitStyle = t.Danger
	}
	facts := []ui.Fact{{Label: "service", Value: unitValue, Style: &unitStyle}}

	// Where the settings came from. It is the first thing that decides how
	// much the rest of the screen is worth, so it is not buried.
	configValue, configStyle := "effective", t.OK
	if !a.model.Effective {
		configValue, configStyle = "from files", t.Warn
	}
	facts = append(facts, ui.Fact{Label: "config", Value: configValue, Style: &configStyle})

	findings := a.model.Findings()
	if count := len(findings); count > 0 {
		style := t.Warn
		for _, finding := range findings {
			if finding.Verdict == ssh.VerdictRisk {
				style = t.Danger
				break
			}
		}
		facts = append(facts, ui.Fact{Label: "findings",
			Value: strconv.Itoa(count), Style: &style})
	}
	facts = append(facts,
		ui.Fact{Label: "sessions", Value: strconv.Itoa(len(a.model.Sessions))})
	if a.model.Auth.Failed > 0 {
		style := t.Warn
		facts = append(facts, ui.Fact{Label: "failed " + a.model.Auth.Window,
			Value: strconv.Itoa(a.model.Auth.Failed), Style: &style})
	}
	// The backend version, when it was probed: quiet on a tested version,
	// coloured on one nobody has run against.
	if a.backendCompat.Backend != "" {
		facts = append(facts, ui.CompatFact(t, a.backendCompat))
	}

	subtitle := a.backend.Describe()
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}
	return ui.Header{Title: "tui-ssh", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// tabsView renders the five screens as one row, with the current one accented.
func (a *app) tabsView() string {
	var parts []string
	for s := screen(0); s < screenCount; s++ {
		label := strconv.Itoa(int(s)+1) + " " + s.title()
		if s == a.screen {
			parts = append(parts, a.theme.Accent.Render("["+label+"]"))
			continue
		}
		parts = append(parts, a.theme.Muted.Render(" "+label+" "))
	}
	return a.theme.Footer.Width(a.width).Render(
		ui.Truncate(strings.Join(parts, " "), a.width-2))
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	count := strconv.Itoa(a.rowCount())
	suffix := "  ·  tab to move  ·  ? for help"
	switch a.screen {
	case screenSessions:
		return count + " open sessions" + suffix
	case screenAuth:
		return count + " events in the last " + a.model.Auth.Window +
			"  ·  w switches the window" + suffix
	case screenHostKeys:
		return count + " host keys" + suffix
	case screenService:
		return a.model.Service.Unit + suffix
	case screenUsers:
		return count + " rows  ·  A adds a key, R removes one" + suffix
	default:
		return count + " settings  ·  e changes one" + suffix
	}
}

// table renders the current screen's rows.
func (a *app) table() string {
	columns, rows, styles := a.tableData()
	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.cursor[a.screen],
		Offset:   a.offset[a.screen],
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// tableData builds the columns, cells and row styles of the current screen.
// Every screen drops its widest columns first on a narrow terminal, which is
// what keeps a 40-column pane readable.
func (a *app) tableData() ([]ui.Column, [][]string, []*lipgloss.Style) {
	switch a.screen {
	case screenSessions:
		return a.sessionsTable()
	case screenAuth:
		return a.authTable()
	case screenHostKeys:
		return a.hostKeysTable()
	case screenService:
		return a.serviceTable()
	case screenUsers:
		return a.usersTable()
	default:
		return a.configTable()
	}
}

// usersTable is the accounts and the public keys that can log into them.
func (a *app) usersTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "USER", Width: 12, Flex: true},
		{Title: "TYPE", Width: 9},
		{Title: "FINGERPRINT", Width: 26, Flex: true},
	}
	showComment := a.width >= 80
	if showComment {
		columns = append(columns, ui.Column{Title: "COMMENT", Width: 20, Flex: true})
	}

	rows := make([][]string, 0, len(a.userRows))
	styles := make([]*lipgloss.Style, 0, len(a.userRows))
	for _, row := range a.userRows {
		cells := []string{row.user.Name, orNone(row.key.Type),
			orNone(row.key.Fingerprint)}
		if !row.hasKey {
			cells[2] = noKeysCell(row.user)
		}
		if showComment {
			cells = append(cells, orNone(row.key.Comment))
		}
		rows = append(rows, cells)
		styles = append(styles, a.userRowStyle(row))
	}
	return columns, rows, styles
}

// noKeysCell says why an account has no key listed, which is not always the
// same answer.
func noKeysCell(user ssh.User) string {
	if user.Unreadable != "" {
		return "(could not read " + user.KeysPath + ")"
	}
	return "(no authorized key)"
}

// userRowStyle greys out the rows that are not a key, so a screen of accounts
// reads as the list of keys it mostly is.
func (a *app) userRowStyle(row userRow) *lipgloss.Style {
	var style lipgloss.Style
	switch {
	case row.hasKey:
		style = a.theme.Row
	case row.user.Unreadable != "":
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	default:
		style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	}
	return &style
}

// configTable is the settings list: the keyword, the value in force, the
// verdict, and the file that decided it.
func (a *app) configTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "SETTING", Width: 24, Flex: true},
		{Title: "VALUE", Width: 18, Flex: true},
		{Title: "", Width: 4},
	}
	showSource := a.width >= 84
	if showSource {
		columns = append(columns, ui.Column{Title: "SET AT", Width: 30, Flex: true})
	}

	rows := make([][]string, 0, len(a.settings))
	styles := make([]*lipgloss.Style, 0, len(a.settings))
	for _, setting := range a.settings {
		row := []string{setting.Key, setting.Value, verdictMark(setting.Verdict)}
		if showSource {
			row = append(row, sourceCell(setting))
		}
		rows = append(rows, row)
		styles = append(styles, a.verdictStyle(setting.Verdict, setting.Security))
	}
	return columns, rows, styles
}

// sourceCell says where a setting came from: the file and line that set it,
// or that nobody did and this is sshd's own default.
func sourceCell(setting ssh.Setting) string {
	if winner, ok := setting.Winner(); ok {
		return winner.String()
	}
	if len(setting.Sources) > 0 {
		// Only ever set inside a Match block, so it applies to some
		// connections and not to the ones this row's value describes.
		return "only inside a Match block"
	}
	return "(default)"
}

// sessionsTable is the live logins.
func (a *app) sessionsTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "USER", Width: 12, Flex: true},
		{Title: "FROM", Width: 18, Flex: true},
		{Title: "TTY", Width: 8},
	}
	showSince := a.width >= 72
	showSession := a.width >= 90
	if showSince {
		columns = append(columns, ui.Column{Title: "SINCE", Width: 22, Flex: true})
	}
	if showSession {
		columns = append(columns, ui.Column{Title: "SESSION", Width: 8})
	}

	rows := make([][]string, 0, len(a.sessions))
	for _, session := range a.sessions {
		row := []string{session.User, session.RemoteIP, orNone(session.TTY)}
		if showSince {
			row = append(row, session.Since)
		}
		if showSession {
			row = append(row, orNone(session.ID))
		}
		rows = append(rows, row)
	}
	return columns, rows, nil
}

// authTable is the authentication log, newest first.
func (a *app) authTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "WHAT", Width: 13},
		{Title: "USER", Width: 12, Flex: true},
		{Title: "FROM", Width: 16, Flex: true},
	}
	showMethod := a.width >= 70
	if showMethod {
		columns = append(columns, ui.Column{Title: "METHOD", Width: 10})
	}

	rows := make([][]string, 0, len(a.events))
	styles := make([]*lipgloss.Style, 0, len(a.events))
	for _, event := range a.events {
		row := []string{event.Kind, orNone(event.User), orNone(event.IP)}
		if showMethod {
			row = append(row, orNone(event.Method))
		}
		rows = append(rows, row)
		styles = append(styles, a.eventStyle(event))
	}
	return columns, rows, styles
}

// hostKeysTable is the server's own keys.
func (a *app) hostKeysTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "TYPE", Width: 9},
		{Title: "BITS", Width: 5},
		{Title: "FINGERPRINT", Width: 24, Flex: true},
		{Title: "", Width: 4},
	}
	rows := make([][]string, 0, len(a.hostKeys))
	styles := make([]*lipgloss.Style, 0, len(a.hostKeys))
	for _, key := range a.hostKeys {
		rows = append(rows, []string{
			orNone(key.Type), strconv.Itoa(key.Bits), key.Fingerprint,
			verdictMark(key.Verdict),
		})
		styles = append(styles, a.verdictStyle(key.Verdict, true))
	}
	return columns, rows, styles
}

// serviceRow is one line of the service screen: a fact and its value.
type serviceRow struct{ label, value string }

// serviceRows flattens the service into rows, so the screen scrolls and
// filters like the other four.
func (a *app) serviceRows() []serviceRow {
	service := a.model.Service
	rows := []serviceRow{
		{"unit", service.Unit},
		{"active", orNone(service.ActiveState)},
		{"enabled", orNone(service.UnitFileState)},
		{"since", orNone(service.Since)},
	}
	for _, listener := range service.Listeners {
		value := listener.String()
		if listener.Process != "" {
			value += "  " + listener.Process
		}
		rows = append(rows, serviceRow{"listening", value})
	}
	if len(service.Listeners) == 0 {
		rows = append(rows, serviceRow{"listening",
			"— (ss reported nothing; it needs no privileges, so this is unusual)"})
	}
	for _, guard := range service.Guards {
		rows = append(rows, serviceRow{guard.Name, guard.Unit + " is " + guard.State})
	}
	if len(service.Guards) == 0 {
		rows = append(rows, serviceRow{"blockers",
			"neither fail2ban nor sshguard is installed"})
	}
	if a.model.Firewall != "" {
		rows = append(rows, serviceRow{"firewall",
			a.model.Firewall + " is active, so b can block an address"})
	} else {
		rows = append(rows, serviceRow{"firewall",
			"no ufw running; blocking an address is a job for tui-firewall"})
	}
	if !a.model.Effective {
		rows = append(rows, serviceRow{"config read", a.model.EffectiveReason})
	}
	for _, file := range a.model.Files {
		if file.Unreadable != "" {
			rows = append(rows, serviceRow{"unreadable", file.Unreadable})
		}
	}
	return rows
}

// serviceTable renders those rows.
func (a *app) serviceTable() ([]ui.Column, [][]string, []*lipgloss.Style) {
	columns := []ui.Column{
		{Title: "", Width: 12},
		{Title: "", Width: 40, Flex: true},
	}
	entries := a.serviceRows()
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.label, entry.value})
	}
	return columns, rows, nil
}

// verdictMark is the one-glyph verdict column. It is a symbol rather than a
// word because the column has to survive a 40-column terminal, and it is
// backed by the color of the row for anyone who cannot tell them apart.
func verdictMark(verdict ssh.Verdict) string {
	switch verdict {
	case ssh.VerdictRisk:
		return "!!"
	case ssh.VerdictWarn:
		return "!"
	case ssh.VerdictOK:
		return "ok"
	default:
		return ""
	}
}

// verdictStyle colors a row by its verdict, so what is wrong stands out from
// what is merely set.
func (a *app) verdictStyle(verdict ssh.Verdict, security bool) *lipgloss.Style {
	var style lipgloss.Style
	switch {
	case verdict == ssh.VerdictRisk:
		style = a.theme.Row.Foreground(a.theme.Danger.GetForeground())
	case verdict == ssh.VerdictWarn:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	case verdict == ssh.VerdictOK:
		style = a.theme.Row.Foreground(a.theme.OK.GetForeground())
	case !security:
		style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	default:
		style = a.theme.Row
	}
	return &style
}

// eventStyle colors a log line by what it was.
func (a *app) eventStyle(event ssh.AuthEvent) *lipgloss.Style {
	var style lipgloss.Style
	switch event.Kind {
	case ssh.AuthAccepted:
		style = a.theme.Row.Foreground(a.theme.OK.GetForeground())
	case ssh.AuthInvalidUser:
		style = a.theme.Row.Foreground(a.theme.Danger.GetForeground())
	case ssh.AuthFailed:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	default:
		style = a.theme.Row
	}
	return &style
}

// detailView renders the selected row in full.
func (a *app) detailView() string {
	header := a.headerView()
	tabs := a.tabsView()
	lines := a.detailLines()

	height := a.detailHeight()
	offset := min(a.detailOffset, max(len(lines)-height, 0))
	a.detailOffset = offset
	end := min(offset+height, len(lines))

	body := make([]string, 0, height)
	for _, line := range lines[offset:end] {
		body = append(body, a.theme.Row.Width(a.width).Render(
			ui.Truncate(line, a.width-2)))
	}
	for i := len(body); i < height; i++ {
		body = append(body, a.theme.Row.Width(a.width).Render(""))
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	position := strconv.Itoa(offset+1) + "–" + strconv.Itoa(end) +
		" of " + strconv.Itoa(len(lines)) + " lines  ·  esc to go back"
	status := ui.StatusLine(a.theme, a.statusKind, a.status, position, a.width)
	return strings.Join([]string{header, tabs,
		strings.Join(body, "\n"), help, status}, "\n")
}

// detailLines builds the detail screen's text for whichever row is selected.
// It returns plain strings so the screen can be scrolled and width-truncated
// in one place.
func (a *app) detailLines() []string {
	switch a.screen {
	case screenSessions:
		return a.sessionDetail()
	case screenAuth:
		return a.eventDetail()
	case screenHostKeys:
		return a.hostKeyDetail()
	case screenService:
		return a.serviceDetail()
	case screenUsers:
		return a.userDetail()
	default:
		return a.settingDetail()
	}
}

// userDetail shows one account and the key selected on it: where the file is,
// what the key is, and what the two keys on this screen do.
func (a *app) userDetail() []string {
	row, ok := a.selectedUserRow()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{
		"Account: " + row.user.Name,
		"",
		"  home           " + orNone(row.user.Home),
		"  group          " + orNone(row.user.Group),
		"  keys file      " + orNone(row.user.KeysPath),
		"  keys           " + strconv.Itoa(len(row.user.Keys)),
	}
	if row.user.Unreadable != "" {
		lines = append(lines, "",
			"  "+row.user.KeysPath+" could not be read:",
			"  "+row.user.Unreadable,
			"",
			"  Re-run with sudo, or as root, to see whose keys are on this account.")
		return lines
	}

	if row.hasKey {
		lines = append(lines, "", "Selected key",
			"  line           "+strconv.Itoa(row.key.Line),
			"  type           "+orNone(row.key.Type),
			"  bits           "+orZero(row.key.Bits),
			"  fingerprint    "+orNone(row.key.Fingerprint),
			"  comment        "+orNone(row.key.Comment))
		if row.key.Options != "" {
			lines = append(lines, "  options        "+row.key.Options)
		}
		lines = append(lines, "",
			"Whoever holds the private half of this key can log in as "+
				row.user.Name+".",
			"",
			"  press R to remove this key, A to add another")
		return lines
	}
	lines = append(lines, "",
		"Nobody has a public key on this account, so nobody logs into it with",
		"one. Whether a password would work is the config screen's question:",
		"PasswordAuthentication, and PermitRootLogin for root.",
		"",
		"  press A to add a key")
	return lines
}

// settingDetail shows one keyword: what it is, what tui-ssh thinks of it, and
// every place it is written.
func (a *app) settingDetail() []string {
	setting, ok := a.selectedSetting()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{
		setting.Key,
		"",
		"  value          " + orNone(setting.Value),
		"  read from      " + readFrom(setting),
		"  verdict        " + orNone(string(setting.Verdict)),
	}
	if setting.Note != "" {
		lines = append(lines, "", "  "+setting.Note)
	}

	lines = append(lines, "", "Written at")
	if len(setting.Sources) == 0 {
		lines = append(lines,
			"  (nowhere — this is sshd's own default for this keyword)")
	}
	for i, source := range setting.Sources {
		marker := "        "
		if i == 0 && source.Match == "" {
			// sshd takes the first value it is given, so the first file-scope
			// occurrence is the one that decides. Saying which is the whole
			// reason this screen exists.
			marker = "  wins  "
		}
		line := marker + source.String() + "   " + source.Text
		if source.Match != "" {
			line += "   (inside Match " + source.Match + ")"
		}
		lines = append(lines, line)
	}

	if a.editable(setting.Key) {
		lines = append(lines, "", "  press e to change it, written to "+
			a.caps.DropInPath)
	} else {
		lines = append(lines, "", "  tui-ssh does not edit this keyword; "+
			"change it in the file above and press r to reload")
	}
	return lines
}

// readFrom says whether a value is what sshd reported or what a file says.
func readFrom(setting ssh.Setting) string {
	if setting.Effective {
		return "`sshd -T`, which is the server's own answer"
	}
	return "the configuration files, not from sshd itself"
}

// sessionDetail shows one login in full.
func (a *app) sessionDetail() []string {
	session, ok := a.selectedSession()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{
		session.Label(),
		"",
		"  user           " + orNone(session.User),
		"  from           " + orNone(session.RemoteIP),
		"  remote port    " + orZero(session.RemotePort),
		"  local port     " + orZero(session.LocalPort),
		"  tty            " + orNone(session.TTY),
		"  since          " + orNone(session.Since),
		"  state          " + orNone(session.State),
		"  leader pid     " + orZero(session.Leader),
	}
	if session.ID == "" {
		lines = append(lines, "",
			"  logind knows nothing about this connection, so there is no",
			"  session to terminate. It is a socket the kernel reports on the",
			"  port sshd listens on: an sftp transfer or a forced command.")
		return lines
	}
	lines = append(lines, "",
		"  press t to end it, b to block "+session.RemoteIP+" at the firewall")
	return lines
}

// eventDetail shows one authentication line, raw.
func (a *app) eventDetail() []string {
	event, ok := a.selectedEvent()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{
		"Authentication event",
		"",
		"  what           " + event.Kind,
		"  user           " + orNone(event.User),
		"  from           " + orNone(event.IP),
		"  method         " + orNone(event.Method),
		"",
		"The line as it was logged",
		"  " + event.Raw,
		"",
		"Read from",
		"  " + orNone(a.model.Auth.Source),
	}
	if event.IP != "" {
		lines = append(lines, "", "  press b to block "+event.IP+" at the firewall")
	}
	return lines
}

// hostKeyDetail shows one host key.
func (a *app) hostKeyDetail() []string {
	key, ok := a.selectedHostKey()
	if !ok {
		return []string{"(nothing selected)"}
	}
	lines := []string{
		"Host key: " + key.Path,
		"",
		"  type           " + orNone(key.Type),
		"  bits           " + orZero(key.Bits),
		"  fingerprint    " + orNone(key.Fingerprint),
		"  comment        " + orNone(key.Comment),
		"  verdict        " + orNone(string(key.Verdict)),
	}
	if key.Note != "" {
		lines = append(lines, "", "  "+key.Note)
	}
	lines = append(lines, "",
		"This is what a client checks against its known_hosts. Compare it by",
		"hand the first time you connect from a new machine; that comparison",
		"is the only thing standing between you and a machine in the middle.",
		"",
		"  press K to replace every host key on this server")
	return lines
}

// serviceDetail shows the service rows plus the counts the auth screen
// summarises, which is the closest thing this tool has to an overview.
func (a *app) serviceDetail() []string {
	lines := []string{"Service", ""}
	for _, row := range a.serviceRows() {
		lines = append(lines, "  "+ui.Pad(row.label, 14)+" "+row.value)
	}
	lines = append(lines, "", "Authentication over the last "+a.model.Auth.Window)
	lines = append(lines,
		"  accepted       "+strconv.Itoa(a.model.Auth.Accepted),
		"  failed         "+strconv.Itoa(a.model.Auth.Failed),
		"  invalid user   "+strconv.Itoa(a.model.Auth.InvalidUser))
	if len(a.model.Auth.TopIPs) > 0 {
		lines = append(lines, "", "Busiest addresses")
		for _, count := range a.model.Auth.TopIPs {
			lines = append(lines, "  "+ui.Pad(count.Name, 20)+" "+
				strconv.Itoa(count.Count))
		}
	}
	if len(a.model.Auth.TopUsers) > 0 {
		lines = append(lines, "", "Accounts being tried")
		for _, count := range a.model.Auth.TopUsers {
			lines = append(lines, "  "+ui.Pad(count.Name, 20)+" "+
				strconv.Itoa(count.Count))
		}
	}
	return lines
}

// orNone renders an empty value as a visible placeholder, so a blank line is
// never mistaken for a missing read.
func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// orZero renders a number, with a placeholder for the zero that means unknown.
func orZero(value int) string {
	if value == 0 {
		return "—"
	}
	return strconv.Itoa(value)
}

// dialogDiffLines is the most diff the confirm dialog will show. The kit's
// dialog does not scroll, so a diff longer than the terminal would push its
// own title and the command preview off the screen — and the command preview
// is the one thing that must never be missed.
const dialogDiffLines = 12

// diffForDialog trims a diff to what fits above the command preview, saying
// how much was left out.
func (a *app) diffForDialog(diff string) string {
	budget := max(min(a.height-14, dialogDiffLines), 4)
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) <= budget {
		return diff
	}
	kept := append([]string{}, lines[:budget]...)
	return strings.Join(kept, "\n") + "\n… " +
		strconv.Itoa(len(lines)-budget) + " more diff lines"
}

// shortHelpKeys is the single-line hint bar, which changes with the screen
// because the keys that do anything change with it.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "tab", Desc: "screen"}, {Key: "enter", Desc: "detail"}}
	switch a.screen {
	case screenSessions:
		hints = append(hints,
			ui.KeyHint{Key: "t", Desc: "end session"},
			ui.KeyHint{Key: "b", Desc: "block"})
	case screenAuth:
		hints = append(hints,
			ui.KeyHint{Key: "w", Desc: "24h/7d"},
			ui.KeyHint{Key: "b", Desc: "block"})
	case screenHostKeys:
		hints = append(hints, ui.KeyHint{Key: "K", Desc: "regenerate"})
	case screenService:
		hints = append(hints, ui.KeyHint{Key: "r", Desc: "reload"})
	case screenUsers:
		hints = append(hints,
			ui.KeyHint{Key: "A", Desc: "add key"},
			ui.KeyHint{Key: "R", Desc: "remove key"})
	default:
		hints = append(hints, ui.KeyHint{Key: "e", Desc: "change"},
			ui.KeyHint{Key: "m", Desc: "match"},
			ui.KeyHint{Key: "r", Desc: "reload"})
	}
	return append(hints,
		ui.KeyHint{Key: "/", Desc: "filter"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"})
}

// helpKeys is the full key list shown on the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab / 1-6", Desc: "config, sessions, auth log, host keys, service, users"},
		{Key: "↑/k, ↓/j", Desc: "move the selection, or scroll the detail screen"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "enter", Desc: "open the selected row in full"},
		{Key: "esc", Desc: "leave the detail screen"},
		{Key: "/", Desc: "filter this screen (esc clears)"},
		{Key: "e", Desc: "change a setting, written to a drop-in with a diff"},
		{Key: "m", Desc: "change a setting inside a Match block"},
		{Key: "A", Desc: "add a public key to an account (users screen)"},
		{Key: "R", Desc: "on users, remove the selected key; elsewhere, re-read"},
		{Key: "t", Desc: "end the selected session"},
		{Key: "b", Desc: "block the selected address at the firewall"},
		{Key: "w", Desc: "switch the log window between 24h and 7d"},
		{Key: "K", Desc: "regenerate the host keys, old ones moved aside"},
		{Key: "r", Desc: "reload the SSH service"},
		{Key: "ctrl+r", Desc: "re-read the server, from any screen"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "note", Desc: "sshd_config is never rewritten; a drop-in is written"},
	}
}
