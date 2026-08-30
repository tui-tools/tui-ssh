package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-ssh/internal/openssh"
)

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo — the fake answers to the same name as the real
// backend, so without this the block would read as a live server — that it
// names OpenSSH as what the fake imitates, and that no server was read to
// produce any of it.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{demo: true, report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: openssh\n",
		"features: not probed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportNeverNamesTheUser is the privacy promise in test form: the block
// is pasted into a public issue, so neither the user's name, their host name
// nor a path under their home directory may reach it.
func TestRunReportNeverNamesTheUser(t *testing.T) {
	t.Setenv("HOSTNAME", "workstation")
	t.Setenv("USER", "alice")
	t.Setenv("HOME", "/home/alice")
	t.Setenv("SSH_CONNECTION", "10.0.0.2 22 10.0.0.1 22")

	var out strings.Builder
	if err := runReport(baseConfig(), options{demo: true, report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, forbidden := range []string{"alice", "workstation", "10.0.0.", "/home/"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the report leaked %q:\n%s", forbidden, got)
		}
	}
}

// TestDescribeFeatures renders the probe's verdict on the keyword spellings
// that differ by release, which is what tells "the change did not take" from
// "this OpenSSH has never heard of that keyword".
func TestDescribeFeatures(t *testing.T) {
	features := []compat.Feature{
		{Name: openssh.FeatureIncludeDropins, Since: "8.2"},
		{Name: openssh.FeatureKbdInteractive, Since: "8.7"},
	}

	tests := []struct {
		name    string
		version string
		demo    bool
		want    string
	}{
		{
			name:    "a current release has both",
			version: "9.9",
			want:    "include-dropins yes, kbd-interactive yes",
		},
		{
			name:    "an older one has only the first",
			version: "8.4",
			want:    "include-dropins yes, kbd-interactive no",
		},
		{
			name:    "and one below the minimum has neither",
			version: "7.9",
			want:    "include-dropins no, kbd-interactive no",
		},
		{
			name: "demo probed nothing, and says so rather than claiming both",
			demo: true,
			want: "not probed (the fake accepts every spelling)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := compat.NewCaps(tc.version, features)
			if got := describeFeatures(caps, tc.demo); got != tc.want {
				t.Errorf("describeFeatures = %q, want %q", got, tc.want)
			}
		})
	}
}
