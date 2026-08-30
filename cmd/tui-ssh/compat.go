package main

import (
	"context"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuissh "github.com/tui-tools/tui-ssh"
)

// probeCompat reads the version of the OpenSSH this tool is about to drive.
//
// The facts it is judged against — the minimum version, the versions the lab
// has actually run against, the caveats that apply to a range, and which
// keyword spellings exist on which release — come from the repository's own
// tool.json, embedded in the binary, so there is no second copy of them in the
// code.
//
// The version comes from `ssh -V`, not from the server. OpenSSH prints it on
// standard error and exits non-zero, which the kit's probe handles: it reads
// the combined output and only an empty one is a failure. `sshd -V` would be
// the more obvious question to ask, and it is the wrong one — it was only
// added in OpenSSH 9.6, so on most of the range this tool supports it prints a
// usage error and no version at all.
//
// It never fails: a manifest that cannot be parsed and a missing binary both
// produce the zero Result, whose capability set answers yes to everything —
// which is the right default, because a backend that cannot do what was asked
// refuses in its own words, and that is a better message than a view hidden
// over an unreadable version string.
func probeCompat(ctx context.Context, demo bool) compat.Result {
	// --demo drives an in-memory server; probing the real OpenSSH on the host
	// would report a version that has nothing to do with what is on screen.
	if demo {
		return compat.Result{}
	}
	m, err := manifest.Load(tuissh.ManifestJSON)
	if err != nil {
		return compat.Result{}
	}
	backend, ok := m.Backend(backendName)
	if !ok {
		return compat.Result{}
	}
	return compat.Probe(ctx, backend)
}
