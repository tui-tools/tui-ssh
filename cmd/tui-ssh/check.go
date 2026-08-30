package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// checkTimeout bounds the read. Loading the model shells out to sshd,
// systemctl, ss, loginctl, journalctl and ssh-keygen, and a machine whose
// journal is enormous must not hang a non-interactive check forever.
const checkTimeout = 60 * time.Second

// verdictReport is one judged setting, flattened into the three fields a shell
// script can assert on without walking the model.
type verdictReport struct {
	Key     string      `json:"key"`
	Value   string      `json:"value"`
	Verdict ssh.Verdict `json:"verdict"`
	// Source is the file and line that set it, empty when nothing did and the
	// value is sshd's own default.
	Source string `json:"source,omitempty"`
	Note   string `json:"note,omitempty"`
}

// hostKeyReport is one host key, without the path noise.
type hostKeyReport struct {
	Type        string      `json:"type"`
	Bits        int         `json:"bits"`
	Fingerprint string      `json:"fingerprint"`
	Verdict     ssh.Verdict `json:"verdict"`
}

// checkReport is what --check prints: the verdicts, the counts and the service
// state, plus the model the backend parsed in full.
//
// It is a report of the read path only. --check never builds and never runs a
// mutation: the whole point is that it is safe to run anywhere, including in
// CI against a production-shaped machine.
type checkReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Backend string `json:"backend"`
	// Describe is the backend's own one-line summary, which is where the demo
	// backend says it is a demo.
	Describe string `json:"describe"`

	// Effective reports whether the settings came from `sshd -T` rather than
	// from reading the files, and EffectiveReason says why not when they did
	// not. A smoke test asserts on this before it asserts on a value.
	Effective       bool   `json:"effective"`
	EffectiveReason string `json:"effectiveReason,omitempty"`

	// Verdicts are the security-relevant settings, in the order the screen
	// shows them. Findings counts the ones worse than ok.
	Verdicts []verdictReport `json:"verdicts"`
	Findings int             `json:"findings"`
	Risks    int             `json:"risks"`

	// Sessions is how many logins are open, FailedLogins how many failures the
	// window carried, and AuthWindow which window that was.
	Sessions     int    `json:"sessions"`
	FailedLogins int    `json:"failedLogins"`
	InvalidUsers int    `json:"invalidUsers"`
	Accepted     int    `json:"accepted"`
	AuthWindow   string `json:"authWindow"`

	HostKeys []hostKeyReport `json:"hostKeys"`

	// Unit, Active and Enabled are the service state under the names a script
	// can grep for without reading the nested model.
	Unit    string `json:"unit"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`

	// Compat is what the backend version probe found. It is reported rather
	// than asserted: an untested version is a fact about the machine, not a
	// failure of the read path.
	Compat compat.Result `json:"compat"`
	// Model is the parsed state in full.
	Model ssh.Model `json:"model"`
}

// runCheck exercises the backend's real read path and prints what it parsed as
// JSON. It returns an error when the backend cannot be read, which main turns
// into a non-zero exit — so a caller can treat the exit code alone as the
// verdict.
//
// A machine where `sshd -T` cannot run is not a failure: the files are read
// instead, every setting comes back with Effective false, and the report says
// so. That is the read path working, and it is what the smoke test asserts on
// an unprivileged run.
func runCheck(backend ssh.Backend, backendCompat compat.Result,
	out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx, ssh.Window24h)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	report := checkReport{
		Tool:            toolName,
		Version:         version,
		Backend:         backend.Name(),
		Describe:        backend.Describe(),
		Effective:       model.Effective,
		EffectiveReason: model.EffectiveReason,
		Sessions:        len(model.Sessions),
		FailedLogins:    model.Auth.Failed,
		InvalidUsers:    model.Auth.InvalidUser,
		Accepted:        model.Auth.Accepted,
		AuthWindow:      model.Auth.Window,
		Unit:            model.Service.Unit,
		Active:          model.Service.Active,
		Enabled:         model.Service.Enabled,
		Compat:          backendCompat,
		Model:           model,
	}
	for _, setting := range model.Settings {
		if !setting.Security {
			continue
		}
		row := verdictReport{
			Key:     setting.Key,
			Value:   setting.Value,
			Verdict: setting.Verdict,
			Note:    setting.Note,
		}
		if winner, ok := setting.Winner(); ok {
			row.Source = winner.String()
		}
		report.Verdicts = append(report.Verdicts, row)
		switch setting.Verdict {
		case ssh.VerdictRisk:
			report.Risks++
			report.Findings++
		case ssh.VerdictWarn:
			report.Findings++
		}
	}
	for _, key := range model.HostKeys {
		report.HostKeys = append(report.HostKeys, hostKeyReport{
			Type:        key.Type,
			Bits:        key.Bits,
			Fingerprint: key.Fingerprint,
			Verdict:     key.Verdict,
		})
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
