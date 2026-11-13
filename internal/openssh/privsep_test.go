package openssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// idleSshdMessage is what OpenSSH 9.6p1 on Ubuntu 24.04 prints, and exits 255
// on, for `sshd -T` and `sshd -t -f` alike while ssh.service has not started.
const idleSshdMessage = "Missing privilege separation directory: /run/sshd"

// fakeSshd writes an executable that stands in for sshd: it prints message and
// exits with status. The runner drives it exactly as it drives the real
// binary, so the error and the output are the shapes a real failure has.
func fakeSshd(t *testing.T, message string, status int) *runner.Runner {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd")
	script := "#!/bin/sh\necho '" + message + "' >&2\nexit " + strconv.Itoa(status) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // a test executable in a private temp dir
		t.Fatal(err)
	}
	return &runner.Runner{Bin: path, Name: "sshd"}
}

func TestMissingPrivsepDirReadsTheDirectoryFromSshd(t *testing.T) {
	for _, c := range []struct {
		out, dir    string
		ok, runtime bool
	}{
		{idleSshdMessage, "/run/sshd", true, true},
		{"Missing privilege separation directory: /var/run/sshd", "/var/run/sshd", true, true},
		{"Missing privilege separation directory: /var/empty/sshd", "/var/empty/sshd", true, false},
		{"Missing privilege separation directory: /usr/share/empty.sshd", "/usr/share/empty.sshd", true, false},
		{"Missing privilege separation directory: /run/../etc", "/run/../etc", true, false},
		{"Missing privilege separation directory: /run/a/b", "/run/a/b", true, false},
		{"/tmp/x.conf line 1: Bad configuration option: Bogus", "", false, false},
		{"", "", false, false},
	} {
		dir, ok := MissingPrivsepDir(c.out)
		if dir != c.dir || ok != c.ok {
			t.Errorf("MissingPrivsepDir(%q) = %q, %v; want %q, %v", c.out, dir, ok, c.dir, c.ok)
		}
		if ok && IsRuntimePrivsepDir(dir) != c.runtime {
			t.Errorf("IsRuntimePrivsepDir(%q) = %v, want %v", dir, !c.runtime, c.runtime)
		}
	}
}

func TestBuildEnsurePrivsepDir(t *testing.T) {
	cmd, err := BuildEnsurePrivsepDir("/run/sshd")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"install", "-d", "-m", "0755", "-o", "root", "-g", "root", "/run/sshd"}
	if !reflect.DeepEqual(cmd.Argv, want) {
		t.Errorf("argv = %q, want %q", cmd.Argv, want)
	}
	if !cmd.Destructive {
		t.Errorf("creating a directory as root must be shown as a change")
	}
	for _, dir := range []string{"/var/empty/sshd", "/run/../etc", "/run/a/b", "run/sshd",
		"/run/", "/run/-x", "/etc/sshd"} {
		if _, err := BuildEnsurePrivsepDir(dir); err == nil {
			t.Errorf("BuildEnsurePrivsepDir(%q) built a command", dir)
		}
	}
}

// TestIdleSshdIsExplainedOnTheReadPath: `sshd -T` fails on an idle
// socket-activated server, the files are read instead, and the reason given
// names the idle state rather than reading like a configuration error.
func TestIdleSshdIsExplainedOnTheReadPath(t *testing.T) {
	backend := &Real{sshd: fakeSshd(t, idleSshdMessage, 255)}
	_, effective, reason, dir := backend.loadSettings(context.Background())
	if effective || dir != "/run/sshd" {
		t.Fatalf("effective = %v, privsep dir = %q; want false, /run/sshd", effective, dir)
	}
	if reason == "" {
		t.Errorf("no reason given")
	}

	// The fixture was captured with the service running; idle is the state
	// this is about.
	idle := ubuntuSocketService(t)
	idle.Active, idle.ActiveState = false, "inactive"
	explanation := PrivsepExplanation(dir, idle)
	for _, want := range []string{"idle under socket activation", "/run/sshd",
		"RuntimeDirectory", "systemctl start ssh"} {
		if !strings.Contains(explanation, want) {
			t.Errorf("explanation %q does not say %q", explanation, want)
		}
	}

	// A directory the package ships is a broken installation: explained,
	// never offered.
	broken := PrivsepExplanation("/var/empty/sshd", idle)
	if strings.Contains(broken, "offers") || !strings.Contains(broken, "reinstall") {
		t.Errorf("broken install explanation = %q", broken)
	}
}

// TestIdleSshdDoesNotRefuseTheValue: the pre-check stops at the missing
// directory. The edit returns ErrPrivsepMissing with the fix, the message does
// not call it a refusal, and no plan comes back — in particular not the
// unvalidated one the "could not run" branch would build.
func TestIdleSshdDoesNotRefuseTheValue(t *testing.T) {
	backend := &Real{sshd: fakeSshd(t, idleSshdMessage, 255)}
	idle := ubuntuSocketService(t)
	idle.Active, idle.ActiveState = false, "inactive"
	model := ssh.Model{Service: idle}

	plan, err := backend.BuildSetOption(model, "PasswordAuthentication", "no")
	if !errors.Is(err, ssh.ErrPrivsepMissing) {
		t.Fatalf("err = %v, want ErrPrivsepMissing", err)
	}
	if strings.Contains(err.Error(), "refused") {
		t.Errorf("the message reads as a refusal: %v", err)
	}
	if len(plan.Commands) != 0 || plan.TempPath != "" {
		t.Errorf("a plan came back anyway: %+v", plan)
	}
	var privsep *ssh.PrivsepMissingError
	if !errors.As(err, &privsep) || privsep.Fix == nil ||
		privsep.Fix.String() != "install -d -m 0755 -o root -g root /run/sshd" {
		t.Fatalf("fix = %+v", privsep)
	}

	// The same for a Match block.
	_, err = backend.BuildSetMatchOption(model, "User", "deploy",
		"PasswordAuthentication", "no")
	if !errors.Is(err, ssh.ErrPrivsepMissing) {
		t.Errorf("match edit: err = %v, want ErrPrivsepMissing", err)
	}

	// A directory outside /run is explained but has no fix to offer.
	backend.sshd = fakeSshd(t, "Missing privilege separation directory: /var/empty/sshd", 255)
	_, err = backend.BuildSetOption(model, "PasswordAuthentication", "no")
	if !errors.As(err, &privsep) || privsep.Fix != nil {
		t.Errorf("/var/empty/sshd: err = %v, fix = %+v", err, privsep)
	}
}

// TestARealRefusalIsStillARefusal keeps the other two branches as they were.
func TestARealRefusalIsStillARefusal(t *testing.T) {
	backend := &Real{sshd: fakeSshd(t, "/tmp/x.conf line 1: Bad configuration option: Bogus", 255)}
	_, err := backend.BuildSetOption(ssh.Model{}, "PasswordAuthentication", "no")
	if err == nil || errors.Is(err, ssh.ErrPrivsepMissing) ||
		!strings.Contains(err.Error(), "sshd refused the file") {
		t.Errorf("err = %v, want a refusal", err)
	}

	backend = &Real{sshd: fakeSshd(t, "", 0)}
	plan, err := backend.BuildSetOption(ssh.Model{Service: ssh.Service{Unit: "sshd"}},
		"PasswordAuthentication", "no")
	if plan.TempPath != "" {
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(plan.TempPath)) })
	}
	if err != nil || !plan.Validated {
		t.Errorf("accepted file: plan = %+v, err = %v", plan, err)
	}
}

// TestIdleDemoCreatesTheDirectoryThenChecks drives the fake the way --demo-idle
// does: the edit is refused for the directory, the fix runs, and then the same
// edit is checked and planned.
func TestIdleDemoCreatesTheDirectoryThenChecks(t *testing.T) {
	fake := NewIdleFake()
	model, err := fake.Load(context.Background(), ssh.Window24h)
	if err != nil {
		t.Fatal(err)
	}
	if model.Effective || !model.PrivsepMissing || model.PrivsepDir != "/run/sshd" ||
		!strings.Contains(model.EffectiveReason, "idle") {
		t.Fatalf("idle model = effective %v, privsep %v %q, reason %q", model.Effective,
			model.PrivsepMissing, model.PrivsepDir, model.EffectiveReason)
	}
	_, err = fake.BuildSetOption(model, "PasswordAuthentication", "no")
	var privsep *ssh.PrivsepMissingError
	if !errors.As(err, &privsep) || privsep.Fix == nil {
		t.Fatalf("err = %v", err)
	}
	if _, err := fake.Run(context.Background(), *privsep.Fix); err != nil {
		t.Fatal(err)
	}
	model, _ = fake.Load(context.Background(), ssh.Window24h)
	if !model.Effective || model.PrivsepMissing {
		t.Errorf("after the fix: effective %v, privsep %v", model.Effective, model.PrivsepMissing)
	}
	plan, err := fake.BuildSetOption(model, "PasswordAuthentication", "no")
	if err != nil || !plan.Validated {
		t.Errorf("retry: plan validated %v, err %v", plan.Validated, err)
	}
}
