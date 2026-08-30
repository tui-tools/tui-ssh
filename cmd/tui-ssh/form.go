package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The two fields of the editor, named rather than numbered so the picker knows
// which one it is filling.
const (
	fieldKey   = "key"
	fieldValue = "value"
)

// settingForm is the guided editor for one sshd keyword.
//
// It is two fields, and that is the whole design: pick the setting, pick the
// value. A form that offered the file, the section and free text would be a
// worse editor than vi with none of its power; what this one is for is the
// handful of keywords whose value decides who can log in, offered with the
// values sshd actually accepts so a typo cannot reach /etc.
type settingForm struct {
	// keys are the keywords on offer, and keyIndex is the one selected.
	keys     []string
	keyIndex int

	// valueOptions is the closed set of values for the selected keyword, nil
	// when the keyword takes free text.
	valueOptions []string
	valueChoice  int
	input        textinput.Model

	// active is 0 for the keyword field and 1 for the value.
	active int
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
	f := settingForm{keys: caps.EditableKeys, dropIn: caps.DropInPath}
	for i, candidate := range f.keys {
		if strings.EqualFold(candidate, key) {
			f.keyIndex = i
		}
	}
	f.input = textinput.New()
	f.input.CharLimit = 200
	f.input.Prompt = ""
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
		return
	}
	f.input.Placeholder = f.current
	f.input.SetValue(f.current)
	f.focusActive()
}

// focusActive moves the text cursor to the value field when it is a text box
// and is the field being edited.
func (f *settingForm) focusActive() {
	if f.active == 1 && len(f.valueOptions) == 0 {
		f.input.Focus()
		return
	}
	f.input.Blur()
}

// next moves to the following field.
func (f *settingForm) next() {
	f.active = (f.active + 1) % 2
	f.focusActive()
}

// prev moves to the previous field. With two fields it is the same move as
// next, and spelling it out separately would only invite them to drift apart.
func (f *settingForm) prev() { f.next() }

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

// activeIsChoice reports whether the active field is one the picker serves.
// The keyword always is; the value is when the keyword has a closed value set.
func (f settingForm) activeIsChoice() bool {
	return f.active == 0 || len(f.valueOptions) > 0
}

// activeKey names the field the picker is about to fill.
func (f settingForm) activeKey() string {
	if f.active == 0 {
		return fieldKey
	}
	return fieldValue
}

// activeLabel, activeOptions and activeValue expose the active field to the
// picker dialog.
func (f settingForm) activeLabel() string {
	if f.active == 0 {
		return "Setting"
	}
	return f.key()
}

func (f settingForm) activeOptions() []string {
	if f.active == 0 {
		return f.keys
	}
	return f.valueOptions
}

func (f settingForm) activeValue() string {
	if f.active == 0 {
		return f.key()
	}
	return f.value()
}

// set applies a value chosen in the picker to a field.
func (f *settingForm) set(field, value string, model ssh.Model,
	caps ssh.Capabilities) {
	if field == fieldKey {
		for i, candidate := range f.keys {
			if candidate == value {
				f.keyIndex = i
				f.reseed(model, caps)
				return
			}
		}
		return
	}
	for i, option := range f.valueOptions {
		if option == value {
			f.valueChoice = i
			return
		}
	}
}

// cycle moves a choice field one step.
func (f *settingForm) cycle(delta int, model ssh.Model, caps ssh.Capabilities) {
	if f.active == 0 {
		if len(f.keys) == 0 {
			return
		}
		f.keyIndex = (f.keyIndex + delta + len(f.keys)) % len(f.keys)
		f.reseed(model, caps)
		return
	}
	if len(f.valueOptions) == 0 {
		return
	}
	f.valueChoice = (f.valueChoice + delta + len(f.valueOptions)) % len(f.valueOptions)
}

// updateActive forwards a message to the value field when it is a text box.
func (f *settingForm) updateActive(msg tea.Msg) tea.Cmd {
	if f.active != 1 || len(f.valueOptions) > 0 {
		return nil
	}
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return cmd
}

// view renders the form as a dialog.
func (f settingForm) view(t theme.Theme, width, height int) string {
	inner := min(max(width-8, 30), 72)
	// The second row's label is the keyword itself, which is longer than any
	// fixed label would be: truncating it to "Permit…" would hide which
	// setting the value belongs to, which is the one thing the row is for.
	labelWidth := min(max(len("Setting"), len(f.key())), max(inner-16, 8))
	valueWidth := max(inner-labelWidth-6, 10)

	lines := []string{t.Title.Render("Change one sshd setting"), ""}
	if f.current != "" {
		lines = append(lines,
			t.Muted.Render("now: ")+t.Base.Render(ui.Truncate(f.current, valueWidth)))
	}
	if f.source != "" {
		lines = append(lines,
			t.Muted.Render("set at: "+ui.Truncate(f.source, valueWidth)), "")
	}

	rows := []struct {
		label  string
		choice bool
		value  string
	}{
		{"Setting", true, f.key()},
		{f.key(), len(f.valueOptions) > 0, f.value()},
	}
	for i, row := range rows {
		label := t.Muted.Render(ui.Pad(ui.Truncate(row.label, labelWidth), labelWidth))
		var value string
		switch {
		case row.choice:
			value = renderChoice(t, row.value, i == f.active, valueWidth)
		case i == f.active:
			input := f.input
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
