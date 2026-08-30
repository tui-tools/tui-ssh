package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-ssh/internal/openssh"
)

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What this function adds is the part only tui-ssh
// knows: the backend it selected, the OpenSSH version the same probe --check
// uses read off `ssh -V`, and which of the manifest's features that version
// has — because the keyword this tool would write is a version question, and a
// bug about the wrong spelling is answered on that line.
//
// It reads no configuration and starts no sshd. --check is the flag that does
// that, and it escalates; a report has to work for a user who cannot, because
// the missing privilege may be the bug. For the same reason a machine with no
// OpenSSH at all still gets a report, with the selection error as one of its
// lines: "there is nothing here to drive" is a bug report, not a refusal.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	// The same probe --check and the header use. There is one version probe in
	// this tool and this is it, and the backend is built from its capability
	// set, so it comes first here as it does in run.
	backendCompat := probeCompat(context.Background(), opts.demo)

	var selected, selectError string
	if backend, err := pickBackend(cfg, opts, backendCompat); err != nil {
		selectError = err.Error()
	} else {
		selected = backend.Name()
	}

	info := report.Info{
		Tool:           toolName,
		Version:        version,
		Backend:        selected,
		BackendVersion: backendCompat.Version,
		BackendDetail:  backendCompat.Detail,
		Demo:           opts.demo,
		Sudo:           cfg.String(config.KeySudo, ""),
		Theme:          palette.Name,
	}
	if opts.demo {
		// The fake answers to the same name as the real backend, so the block
		// would otherwise read as a live server. What it imitates is OpenSSH,
		// which is the parsers and the command builders the session exercised.
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: backendName,
		})
	}
	info.Extra = append(info.Extra, report.Field{
		Key: "features", Value: describeFeatures(backendCompat.Caps(), opts.demo),
	})
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// reportedFeatures are the manifest features whose answer changes what this
// tool writes, in the order the block names them.
var reportedFeatures = []string{
	openssh.FeatureIncludeDropins,
	openssh.FeatureKbdInteractive,
}

// describeFeatures renders the probe's verdict on each of them as one line. A
// report that says only "openssh 8.4" leaves the reader working out for
// themselves which keyword spelling that release accepts, and that difference
// is most of the bugs about a change that did not take.
func describeFeatures(caps compat.Caps, demo bool) string {
	// Nothing was probed in demo mode, and an unprobed capability set answers
	// yes to everything by design — which would read here as a verdict about
	// the machine rather than as the absence of one.
	if demo {
		return "not probed (the fake accepts every spelling)"
	}
	parts := make([]string, 0, len(reportedFeatures))
	for _, name := range reportedFeatures {
		parts = append(parts, name+" "+yesNo(caps.Has(name)))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// yesNo renders a capability the way the block reads it.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you or your server: paste it "+
		"into a %s issue)",
	toolName)
