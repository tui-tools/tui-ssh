package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// editKey opens the editor and switches it to a keyword the sample server
// may not set, with the cursor on the value field.
func editKey(t *testing.T, a *app, key string) {
	t.Helper()
	selectSetting(t, a, "Port")
	drain(t, a, press(a, "e"))
	a.form.set(fieldKey, key, a.model, a.caps)
	drain(t, a, press(a, "tab"))
	if a.form.key() != key || a.form.activeField() != fieldValue {
		t.Fatalf("editor is on %s / %s", a.form.key(), a.form.activeField())
	}
}

// TestFormShowsWhyAValueWasRefused: the form hides the status line, so a
// refused value used to look like an enter key that did nothing. The reason
// now sits under the field it is about, and the form stays open on it.
func TestFormShowsWhyAValueWasRefused(t *testing.T) {
	a, backend := newTestApp(t)
	selectSetting(t, a, "Port")
	drain(t, a, press(a, "e"))
	drain(t, a, press(a, "tab"))
	a.form.input.SetValue("99999")
	drain(t, a, press(a, "enter"))

	if a.mode != modeForm {
		t.Fatalf("mode = %v, want the form to stay open", a.mode)
	}
	if a.form.refusalField != fieldValue {
		t.Errorf("refusal is about %q, want the value field", a.form.refusalField)
	}
	if !strings.Contains(a.form.refusal, "between 1 and 65535") {
		t.Errorf("refusal = %q", a.form.refusal)
	}
	if view := a.View(); !strings.Contains(view, "between 1 and 65535") {
		t.Errorf("the form does not show the reason:\n%s", view)
	}
	if len(backend.Ran()) != 0 {
		t.Errorf("a refused value ran a command")
	}

	// Typing clears it: the reason was about the old value.
	drain(t, a, press(a, "1"))
	if a.form.refusal != "" {
		t.Errorf("the refusal outlived the edit: %q", a.form.refusal)
	}
}

// TestRefusalsNeverEchoTheValue: whatever was pasted into a box (a key, a
// password typed into the wrong field) must not come back in the refusal, on
// the form or in the status line.
func TestRefusalsNeverEchoTheValue(t *testing.T) {
	const secret = "hunter2-Sup3rS3cret"
	cases := []struct {
		name  string
		setup func(a *app)
		field string
	}{
		{"free-text value with a comment", func(a *app) {
			editKey(t, a, "AllowUsers")
			a.form.input.SetValue("ana #" + secret)
		}, fieldValue},
		{"free-text value of the wrong shape", func(a *app) {
			selectSetting(t, a, "MaxAuthTries")
			drain(t, a, press(a, "e"))
			drain(t, a, press(a, "tab"))
			a.form.input.SetValue(secret)
		}, fieldValue},
		{"match address", func(a *app) {
			drain(t, a, press(a, "m"))
			a.form.set(fieldMatchType, "Address", a.model, a.caps)
			a.form.matchInput.SetValue("10.0.0.0/8," + secret)
			a.form.set(fieldKey, "PasswordAuthentication", a.model, a.caps)
			a.form.set(fieldValue, "no", a.model, a.caps)
		}, fieldMatchValue},
		{"match user", func(a *app) {
			drain(t, a, press(a, "m"))
			a.form.set(fieldMatchType, "User", a.model, a.caps)
			a.form.matchInput.SetValue(secret + "/x")
			a.form.set(fieldKey, "PasswordAuthentication", a.model, a.caps)
			a.form.set(fieldValue, "no", a.model, a.caps)
		}, fieldMatchValue},
	}
	for _, tc := range cases {
		a, _ := newTestApp(t)
		tc.setup(a)
		drain(t, a, press(a, "enter"))
		if a.mode != modeForm {
			t.Errorf("%s: mode = %v, want the form with a refusal", tc.name, a.mode)
			continue
		}
		if a.form.refusal == "" || a.form.refusalField != tc.field {
			t.Errorf("%s: refusal %q on field %q, want one on %q", tc.name,
				a.form.refusal, a.form.refusalField, tc.field)
		}
		if strings.Contains(a.form.refusal, "Sup3rS3cret") ||
			strings.Contains(a.status, "Sup3rS3cret") {
			t.Errorf("%s: the refusal echoes the value: %q / %q", tc.name,
				a.form.refusal, a.status)
		}
		if a.form.activeField() != tc.field {
			t.Errorf("%s: the cursor is on %q, want the refused field %q",
				tc.name, a.form.activeField(), tc.field)
		}
	}
}

// TestRefusalMasksAValueSshdQuoted: sshd's parser quotes the line it rejects,
// so a refusal coming from the check is masked before it is shown. An error
// with no field is shown on the form as a whole.
func TestRefusalMasksAValueSshdQuoted(t *testing.T) {
	a, _ := newTestApp(t)
	editKey(t, a, "AllowUsers")
	a.form.input.SetValue("pasted-token-value")

	a.form.refuse(&ssh.FieldError{Field: ssh.FieldValue,
		Reason: "sshd refused the file: line 3: bad user pasted-token-value"})
	if strings.Contains(a.form.refusal, "pasted-token-value") {
		t.Errorf("refusal = %q", a.form.refusal)
	}
	if !strings.Contains(a.form.refusal, "sshd refused the file") {
		t.Errorf("refusal lost its reason: %q", a.form.refusal)
	}

	a.form.refuse(errors.New("could not stage the file"))
	if a.form.refusalField != "" {
		t.Errorf("a general error was attributed to %q", a.form.refusalField)
	}
	if view := a.View(); !strings.Contains(view, "could not stage the file") {
		t.Errorf("the form does not show a general refusal:\n%s", view)
	}
}
