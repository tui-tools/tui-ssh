package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	"github.com/tui-tools/tui-kit/runner"
	tuissh "github.com/tui-tools/tui-ssh"
	"github.com/tui-tools/tui-ssh/internal/openssh"
)

// backend loads the manifest block the binary really reads.
func backend(t *testing.T) compat.Backend {
	t.Helper()
	m, err := manifest.Load(tuissh.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded manifest does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Fatalf("manifest name = %q, want %q", m.Name, toolName)
	}
	b, ok := m.Backend(backendName)
	if !ok {
		t.Fatalf("the manifest declares no %q backend", backendName)
	}
	return b
}

func TestManifestDeclaresTheBackend(t *testing.T) {
	b := backend(t)
	if b.Binary != "ssh" {
		t.Errorf("binary = %q, want ssh", b.Binary)
	}
	// 8.2 is where `Include` arrived, and without `Include` there is no
	// /etc/ssh/sshd_config.d for the editor to write to.
	if b.Minimum != "8.2" {
		t.Errorf("minimum = %q, want 8.2", b.Minimum)
	}
	if len(b.VersionCommand) == 0 {
		t.Errorf("a backend with no version command cannot be probed")
	}
}

// TestVersionRegexReadsRealOutput uses the `ssh -V` banner as it really
// prints, including the OpenSSL version after it, which is full of digits that
// must not be mistaken for OpenSSH's own.
func TestVersionRegexReadsRealOutput(t *testing.T) {
	b := backend(t)
	tests := map[string]string{
		// Captured from the Fedora 42 host this tool was written on.
		"OpenSSH_9.9p1, OpenSSL 3.2.6 30 Sep 2025": "9.9",
		// Ubuntu 24.04 and Debian 12.
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024": "9.6",
		"OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.11 19 Sep 2023":   "9.2",
		// The oldest release this tool claims to work with.
		"OpenSSH_8.2p1 Ubuntu-4ubuntu0.11, OpenSSL 1.1.1f  31 Mar 2020": "8.2",
	}
	for output, want := range tests {
		if got := compat.ParseVersion(output, b.VersionRegex); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", output, got, want)
		}
	}
}

// TestVersionIsReadFromStandardError is the one thing about this backend that
// is not like the others: `ssh -V` prints its banner on standard error and
// exits non-zero. A probe that read only stdout would report nothing at all,
// on every machine, forever.
//
// The kit's runner reads the combined output and the probe treats a non-empty
// one as an answer even when the call failed, so this asserts the whole chain
// rather than the regex alone.
func TestVersionIsReadFromStandardError(t *testing.T) {
	const banner = "OpenSSH_9.9p1, OpenSSL 3.2.6 30 Sep 2025"
	result := compat.ProbeWith(context.Background(), backend(t),
		func(context.Context, []string) (string, error) {
			// What the runner returns for `ssh -V`: the banner it captured,
			// and the non-zero exit as an error.
			return banner, errors.New("`ssh -V` failed: exit status 255")
		})
	if result.Version != "9.9" {
		t.Errorf("version = %q, want 9.9 read off standard error", result.Version)
	}
	if result.Status == compat.StatusUnknown {
		t.Errorf("a version that was read must not classify as unknown")
	}
}

// TestVersionProbeAgainstThisHost runs the real probe when ssh is installed,
// which is the assertion that the manifest's command and regex still match
// what a machine prints — including the part that is easy to get wrong, that
// the banner arrives on standard error with a non-zero exit.
//
// It asserts the shape rather than a number: this runs on whatever OpenSSH the
// machine happens to carry, and pinning that would only mean the test breaks
// every time a CI image is refreshed.
func TestVersionProbeAgainstThisHost(t *testing.T) {
	if !runner.Available("ssh", backend(t).SearchPaths...) {
		t.Skip("no ssh on this machine")
	}
	result := compat.Probe(context.Background(), backend(t))
	if result.Version == "" {
		t.Fatalf("the probe read no version from this host: %s", result.Detail)
	}
	if !versionShape.MatchString(result.Version) {
		t.Errorf("the probe read %q, which is not an OpenSSH version",
			result.Version)
	}
	if result.Status == compat.StatusUnknown {
		t.Errorf("a version that was read must not classify as unknown")
	}
	// And the captured banner, run through the same regex, parses the same way.
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "openssh",
		"testdata", "ssh-version.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if got := compat.ParseVersion(string(raw), backend(t).VersionRegex); got != "9.9" {
		t.Errorf("the captured banner parses as %q, want 9.9", got)
	}
}

// versionShape is what an OpenSSH version looks like once the regex has had it.
var versionShape = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// TestFeatureGatesMatchTheReleases pins what the manifest claims: `Include`
// arrived in 8.2 and the KbdInteractiveAuthentication spelling in 8.7.
func TestFeatureGatesMatchTheReleases(t *testing.T) {
	b := backend(t)
	tests := []struct {
		version      string
		include, kbd bool
	}{
		{"8.1", false, false},
		{"8.2", true, false},
		{"8.6", true, false},
		{"8.7", true, true},
		{"9.9", true, true},
	}
	for _, test := range tests {
		caps := compat.NewCaps(test.version, b.Features)
		if got := caps.Has(openssh.FeatureIncludeDropins); got != test.include {
			t.Errorf("OpenSSH %s: include-dropins = %v, want %v",
				test.version, got, test.include)
		}
		if got := caps.Has(openssh.FeatureKbdInteractive); got != test.kbd {
			t.Errorf("OpenSSH %s: kbd-interactive = %v, want %v",
				test.version, got, test.kbd)
		}
	}
}

// TestUnknownVersionKeepsEveryFeature: a version the probe could not read must
// not hide a working view. The backend refuses in its own words instead.
func TestUnknownVersionKeepsEveryFeature(t *testing.T) {
	caps := compat.Result{}.Caps()
	if !caps.Has(openssh.FeatureIncludeDropins) ||
		!caps.Has(openssh.FeatureKbdInteractive) {
		t.Errorf("an unprobed version must be treated as capable")
	}
}

func TestProbeInDemoModeReportsNothing(t *testing.T) {
	if got := probeCompat(context.Background(), true); got.Backend != "" {
		t.Errorf("--demo probed the host: %+v", got)
	}
}

func TestClassifiesVersionsAgainstTheMinimum(t *testing.T) {
	b := backend(t)
	tests := map[string]compat.Status{
		"8.1": compat.StatusBelowMinimum,
		"8.2": compat.StatusUntested,
		"9.9": compat.StatusUntested,
	}
	for version, want := range tests {
		result := compat.ProbeWith(context.Background(), b,
			func(context.Context, []string) (string, error) {
				return "OpenSSH_" + version + "p1, OpenSSL 3.2.6 30 Sep 2025", nil
			})
		if result.Version != version {
			t.Errorf("probed version %q, want %q", result.Version, version)
		}
		// A version in the manifest's tested list would classify as tested;
		// the expectations above hold while that list is short, so they are
		// skipped for a version the evidence file already covers.
		if isTested(b, version) {
			continue
		}
		if result.Status != want {
			t.Errorf("OpenSSH %s: status %v, want %v", version, result.Status, want)
		}
	}
}

// TestNotesCoverTheRanges: every caveat the README prints has to apply to some
// version, or it is documentation nobody will ever be shown.
func TestNotesCoverTheRanges(t *testing.T) {
	b := backend(t)
	if len(b.Notes) == 0 {
		t.Fatalf("the manifest declares no notes")
	}
	for _, note := range b.Notes {
		if strings.TrimSpace(note.Impact) == "" {
			t.Errorf("note %q has no impact sentence", note.Range)
		}
		var matched bool
		for _, version := range []string{"8.1", "8.2", "8.6", "8.7", "9.9"} {
			if compat.Match(version, note.Range) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("note %q applies to no version anyone runs", note.Range)
		}
	}
}

// isTested reports whether the manifest already records a passing run.
func isTested(b compat.Backend, version string) bool {
	for _, tested := range b.Tested {
		if tested == version {
			return true
		}
	}
	return false
}
