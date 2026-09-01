package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The fields of the editor, named rather than numbered so the picker knows
// which one it is filling. A file-scope change uses the first two; a change
// inside a `Match` block uses all four.
const (
	fieldKey        = "key"
	fieldValue      = "value"
	fieldMatchType  = "match-type"
	fieldMatchValue = "match-value"
)

// settingForm is the guided editor for one sshd keyword.
//
// It is two fields, and that is the whole design: pick the setting, pick the
// value. A form that offered the file, the section and free text would be a
// worse editor than vi with none of its power; what this one is for is the
// handful of keywords whose value decides who can log in, offered with the
// values sshd actually accepts so a typo cannot reach /etc.
//
// The Match variant adds two fields in front of those — what the block selects
// on, and the value it selects — and nothing else: the same keyword list, the
// same validators, the same one file at the end of it.
type settingForm struct {
	// match reports that this form writes inside a `Match` block.
	match bool
	// fields are the field names in the order tab moves through them, and
	// active is the one being edited.
	fields []string
	active int

	// keys are the keywords on offer, and keyIndex is the one selected.
	keys     []string
	keyIndex int

	// valueOptions is the closed set of values for the selected keyword, nil
	// when the keyword takes free text.
	valueOptions []string
	valueChoice  int
	input        textinput.Model

	// matchTypes are the criteria a block can select on, and matchInput is the
	// value typed for the selected one.
	matchTypes     []string
	matchTypeIndex int
	matchInput     textinput.Model

	// current is what the server reports for this keyword today, and where it
	// is set, shown above the fields so the change has a starting point.
	current string
	source  string
	help    string
	// dropIn is the file the change lands in, named on the form so nobody has
	// to reach the confirm dialog to find out where it is going.
	dropIn string
}

// newSettingForm builds the editor for a keyword, seeded from what the server
// reports today.
func newSettingForm(key string, model ssh.Model, caps ssh.Capabilities) settingForm {
	return newForm(key, model, caps, false)
}

// newMatchForm builds the same editor with the two criteria fields in front of
// it, for a keyword that is to apply only to some connections.
func newMatchForm(key string, model ssh.Model, caps ssh.Capabilities) settingForm {
	return newForm(key, model, caps, true)
}

// newForm is the shared constructor of the two.
func newForm(key string, model ssh.Model, caps ssh.Capabilities,
	match bool) settingForm {
	f := settingForm{
		match:      match,
		fields:     []string{fieldKey, fieldValue},
		keys:       caps.EditableKeys,
		matchTypes: caps.MatchTypes,
		dropIn:     caps.DropInPath,
	}
	if match {
		f.fields = []string{fieldMatchType, fieldMatchValue, fieldKey, fieldValue}
	}
	for i, candidate := range f.keys {
		if strings.EqualFold(candidate, key) {
			f.keyIndex = i
		}
	}
	f.input = textinput.New()
	f.input.CharLimit = 200
	f.input.Prompt = ""
	f.matchInput = textinput.New()
	f.matchInput.CharLimit = 200
	f.matchInput.Prompt = ""
	f.matchInput.Placeholder = "ana,deploy"
	f.reseed(model, caps)
	return f
}

// reseed rebuilds the value field for the selected keyword. It runs whenever
// the keyword changes, because the value field is a picker for one keyword and
// a text box for the next.
func (f *settingForm) reseed(model ssh.Model, caps ssh.Capabilities) {
	key := f.key()
	f.current, f.source = "", ""
	if setting, ok := model.Setting(key); ok {
		f.current = setting.Value
		if winner, found := setting.Winner(); found {
			f.source = winner.String()
		} else {
			f.source = "sshd's own default"
		}
	}
	f.help = caps.Help[key]

	options, closed := caps.ChoicesFor(key)
	f.valueOptions, f.valueChoice = options, 0
	if closed {
		for i, option := range options {
			if option == f.current {
				f.valueChoice = i
			}
		}
		f.input.Blur()
		f.focusActive()
		return
	}
	f.input.Placeholder = f.current
	f.input.SetValue(f.current)
	f.focusActive()
}

// focusActive moves the text cursor into whichever text box is the field being
// edited, and out of the other one.
func (f *settingForm) focusActive() {
	f.input.Blur()
	f.matchInput.Blur()
	switch f.activeField() {
	case fieldValue:
		if len(f.valueOptions) == 0 {
			f.input.Focus()
		}
	case fieldMatchValue:
		f.matchInput.Focus()
	}
}

// next moves to the following field.
func (f *settingForm) next() {
	f.active = (f.active + 1) % len(f.fields)
	f.focusActive()
}

// prev moves to the previous field.
func (f *settingForm) prev() {
	f.active = (f.active + len(f.fields) - 1) % len(f.fields)
	f.focusActive()
}

// activeField names the field being edited.
func (f settingForm) activeField() string {
	if f.active < 0 || f.active >= len(f.fields) {
		return ""
	}
	return f.fields[f.active]
}

// key is the selected keyword.
func (f settingForm) key() string {
	if f.keyIndex < 0 || f.keyIndex >= len(f.keys) {
		return ""
	}
	return f.keys[f.keyIndex]
}

// value is the value the form would write.
func (f settingForm) value() string {
	if len(f.valueOptions) > 0 {
		if f.valueChoice < 0 || f.valueChoice >= len(f.valueOptions) {
			return ""
		}
		return f.valueOptions[f.valueChoice]
	}
	return strings.TrimSpace(f.input.Value())
}

// matchType is the criteria a Match block selects on.
func (f settingForm) matchType() string {
	if f.matchTypeIndex < 0 || f.matchTypeIndex >= len(f.matchTypes) {
		return ""
	}
	return f.matchTypes[f.matchTypeIndex]
}

// matchValue is what that criteria is matched against.
func (f settingForm) matchValue() string {
	return strings.TrimSpace(f.matchInput.Value())
}

// activeIsChoice reports whether the active field is one the picker serves.
// The keyword and the criteria always are; the value is when the keyword has a
// closed value set.
func (f settingForm) activeIsChoice() bool {
	switch f.activeField() {
	case fieldKey, fieldMatchType:
		return true
	case fieldValue:
		return len(f.valueOptions) > 0
	default:
		return false
	}
}

// activeKey names the field the picker is about to fill.
func (f settingForm) activeKey() string { return f.activeField() }

// activeLabel, activeOptions and activeValue expose the active field to the
// picker dialog.
func (f settingForm) activeLabel() string {
	switch f.activeField() {
	case fieldMatchType:
		return "Match on"
	case fieldMatchValue:
		return f.matchType()
	case fieldKey:
		return "Setting"
	default:
		return f.key()
	}
}

func (f settingForm) activeOptions() []string {
	switch f.activeField() {
	case fieldMatchType:
		return f.matchTypes
	case fieldKey:
		return f.keys
	default:
		return f.valueOptions
	}
}

func (f settingForm) activeValue() string {
	switch f.activeField() {
	case fieldMatchType:
		return f.matchType()
	case fieldMatchValue:
		return f.matchValue()
	case fieldKey:
		return f.key()
	default:
		return f.value()
	}
}

// set applies a value chosen in the picker to a field.
func (f *settingForm) set(field, value string, model ssh.Model,
	caps ssh.Capabilities) {
	switch field {
	case fieldKey:
		for i, candidate := range f.keys {
			if candidate == value {
				f.keyIndex = i
				f.reseed(model, caps)
				return
			}
		}
	case fieldMatchType:
		for i, candidate := range f.matchTypes {
			if candidate == value {
				f.matchTypeIndex = i
				return
			}
		}
	case fieldValue:
		for i, option := range f.valueOptions {
			if option == value {
				f.valueChoice = i
				return
			}
		}
	}
}

// cycle moves a choice field one step.
func (f *settingForm) cycle(delta int, model ssh.Model, caps ssh.Capabilities) {
	switch f.activeField() {
	case fieldKey:
		if len(f.keys) == 0 {
			return
		}
		f.keyIndex = (f.keyIndex + delta + len(f.keys)) % len(f.keys)
		f.reseed(model, caps)
	case fieldMatchType:
		if len(f.matchTypes) == 0 {
			return
		}
		f.matchTypeIndex = (f.matchTypeIndex + delta + len(f.matchTypes)) %
			len(f.matchTypes)
	case fieldValue:
		if len(f.valueOptions) == 0 {
			return
		}
		f.valueChoice = (f.valueChoice + delta + len(f.valueOptions)) %
			len(f.valueOptions)
	}
}

// updateActive forwards a message to whichever text box is being edited.
func (f *settingForm) updateActive(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch f.activeField() {
	case fieldValue:
		if len(f.valueOptions) > 0 {
			return nil
		}
		f.input, cmd = f.input.Update(msg)
	case fieldMatchValue:
		f.matchInput, cmd = f.matchInput.Update(msg)
	}
	return cmd
}

// formRow is one line of the rendered form.
type formRow struct {
	label  string
	choice bool
	value  string
	// input is the text box this row is, nil on a choice row.
	input *textinput.Model
}

// rows lays the form out, in field order.
func (f settingForm) rows() []formRow {
	rows := make([]formRow, 0, len(f.fields))
	for _, field := range f.fields {
		switch field {
		case fieldMatchType:
			rows = append(rows, formRow{label: "Match on", choice: true,
				value: f.matchType()})
		case fieldMatchValue:
			rows = append(rows, formRow{label: f.matchType(),
				value: f.matchValue(), input: &f.matchInput})
		case fieldKey:
			rows = append(rows, formRow{label: "Setting", choice: true,
				value: f.key()})
		case fieldValue:
			row := formRow{label: f.key(), choice: len(f.valueOptions) > 0,
				value: f.value()}
			if !row.choice {
				row.input = &f.input
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// title names the dialog, which is the one place the two variants read
// differently: a file-scope change is about the server, a Match change is about
// some of the connections to it.
func (f settingForm) title() string {
	if f.match {
		return "Change one sshd setting inside a Match block"
	}
	return "Change one sshd setting"
}

// view renders the form as a dialog.
func (f settingForm) view(t theme.Theme, width, height int) string {
	inner := min(max(width-8, 30), 72)
	// The value row's label is the keyword itself, which is longer than any
	// fixed label would be: truncating it to "Permit…" would hide which
	// setting the value belongs to, which is the one thing the row is for.
	labelWidth := min(max(len("Match on"), len(f.key())), max(inner-16, 8))
	valueWidth := max(inner-labelWidth-6, 10)

	lines := []string{t.Title.Render(f.title()), ""}
	if f.current != "" {
		lines = append(lines,
			t.Muted.Render("now: ")+t.Base.Render(ui.Truncate(f.current, valueWidth)))
	}
	if f.source != "" {
		lines = append(lines,
			t.Muted.Render("set at: "+ui.Truncate(f.source, valueWidth)), "")
	}

	for i, row := range f.rows() {
		label := t.Muted.Render(ui.Pad(ui.Truncate(row.label, labelWidth), labelWidth))
		var value string
		switch {
		case row.choice:
			value = renderChoice(t, row.value, i == f.active, valueWidth)
		case i == f.active && row.input != nil:
			input := *row.input
			input.Width = valueWidth - 2
			value = input.View()
		default:
			value = t.Base.Render(ui.Truncate(row.value, valueWidth))
		}
		marker := "  "
		if i == f.active {
			marker = t.Accent.Render("> ")
		}
		lines = append(lines, marker+label+"  "+value)
	}

	if f.help != "" {
		lines = append(lines, "", t.Muted.Render(f.help))
	}
	if f.match {
		lines = append(lines, "",
			t.Muted.Render(ui.Truncate(
				"Applies only to connections this block selects.", inner-4)))
	}
	lines = append(lines, "",
		t.Muted.Render(ui.Truncate("Written to "+f.dropIn, inner-4)),
		"",
		t.Key.Render("tab")+t.KeyDesc.Render(" next  ")+
			t.Key.Render("←/→")+t.KeyDesc.Render(" change  ")+
			t.Key.Render("space")+t.KeyDesc.Render(" list  ")+
			t.Key.Render("enter")+t.KeyDesc.Render(" review  ")+
			t.Key.Render("esc")+t.KeyDesc.Render(" cancel"))

	box := t.Dialog.Width(inner).Render(strings.Join(lines, "\n"))
	return placeCenter(box, width, height)
}

// renderChoice draws a choice field with its cycling arrows.
func renderChoice(t theme.Theme, value string, active bool, width int) string {
	value = ui.Truncate(value, width-4)
	if active {
		return t.Accent.Render("‹ ") + t.Base.Render(value) + t.Accent.Render(" ›")
	}
	return t.Base.Render("  " + value)
}
