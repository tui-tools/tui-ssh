package openssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// keysHome builds a home directory under a fresh temporary directory, owned by
// the user running the test, and a model holding the account that lives in it.
// os.MkdirTemp is used rather than t.TempDir because a subtest name can put
// characters in the path that the home check refuses on its own.
func keysHome(t *testing.T) (ssh.Model, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "tuissh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	home := filepath.Join(base, "deploy")
	mustMkdir(t, home)
	user := ssh.User{Name: "deploy", Group: "deploy", Home: home,
		UID: os.Getuid(), KeysPath: AuthorizedKeysPathFor(home)}
	return ssh.Model{Users: []ssh.User{user}}, home
}

func mustMkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.Mkdir(name, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// victimKeys is the file somebody would like their key, or their ownership,
// to end up in.
const victimKeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVu7l48AcDeT36Odle6Mnflh5Bs" +
	"VHir2huMQEf+qt4Z root@admin\n"

// pastedKey is a well-formed key to add.
const pastedKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVu7l48AcDeT36Odle6Mnflh5Bs" +
	"VHir2huMQEf+qt4Z deploy@laptop"

// secondKey is another well-formed key, for adding to a file that already
// holds pastedKey's blob.
const secondKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqzotOhqPdHsY1mZQK50Ss3p4CZ" +
	"V9j/O/hIlt3kcN67 deploy@phone"

// TestKeyChangesRefuseARedirectedName is the regression test for writes that
// followed the account's own symlinks with root's privileges: whatever the
// names under ~/.ssh point at, no plan is built and the users screen reports
// the refusal instead of listing the other file's keys.
func TestKeyChangesRefuseARedirectedName(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, model *ssh.Model, home string)
		want  string
	}{
		{
			name: "~/.ssh is a symlink to another account's directory",
			setup: func(t *testing.T, _ *ssh.Model, home string) {
				victim := filepath.Join(filepath.Dir(home), "other")
				mustMkdir(t, victim)
				mustWrite(t, filepath.Join(victim, "authorized_keys"), victimKeys)
				mustSymlink(t, victim, filepath.Join(home, ".ssh"))
			},
			want: "/.ssh is a symbolic link",
		},
		{
			name: "authorized_keys is a symlink to another account's file",
			setup: func(t *testing.T, _ *ssh.Model, home string) {
				victim := filepath.Join(filepath.Dir(home), "victim_keys")
				mustWrite(t, victim, victimKeys)
				mustMkdir(t, filepath.Join(home, ".ssh"))
				mustSymlink(t, victim, filepath.Join(home, ".ssh", "authorized_keys"))
			},
			want: "authorized_keys is a symbolic link",
		},
		{
			name: "~/.ssh belongs to somebody else",
			setup: func(t *testing.T, model *ssh.Model, home string) {
				mustMkdir(t, filepath.Join(home, ".ssh"))
				mustWrite(t, filepath.Join(home, ".ssh", "authorized_keys"), victimKeys)
				// The files belong to whoever runs the test; the account is
				// made somebody else, which is the same mismatch.
				model.Users[0].UID = os.Getuid() + 1
			},
			want: "belongs to uid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, home := keysHome(t)
			tc.setup(t, &model, home)
			backend := &Real{programs: ProgramNames}

			if _, err := backend.BuildAddAuthorizedKey(model, "deploy",
				pastedKey); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("add: error = %v, want one containing %q", err, tc.want)
			}
			fingerprint := ParseAuthorizedKeys(victimKeys)[0].Fingerprint
			if _, err := backend.BuildRemoveAuthorizedKey(model, "deploy",
				fingerprint); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("remove: error = %v, want one containing %q", err, tc.want)
			}

			loaded := LoadAuthorizedKeys(model.Users,
				func(path string) (string, error) {
					return backend.readKeys(t.Context(), model.Users[0])
				})
			if len(loaded[0].Keys) != 0 {
				t.Errorf("the users screen lists %d keys read through the "+
					"redirected name", len(loaded[0].Keys))
			}
			if !strings.Contains(loaded[0].Unreadable, tc.want) {
				t.Errorf("Unreadable = %q, want one containing %q",
					loaded[0].Unreadable, tc.want)
			}
		})
	}
}

// TestKeyChangesOnAnOrdinaryHome is the other half: an account's own ~/.ssh,
// present or not, still gets a plan, and every command in it runs as the
// account.
func TestKeyChangesOnAnOrdinaryHome(t *testing.T) {
	backend := &Real{programs: ProgramNames}

	t.Run("no ~/.ssh yet", func(t *testing.T) {
		model, _ := keysHome(t)
		plan, err := backend.BuildAddAuthorizedKey(model, "deploy", pastedKey)
		if err != nil {
			t.Fatalf("BuildAddAuthorizedKey: %v", err)
		}
		assertRunAsAccount(t, "deploy", plan.Commands)
		// The directory, then an empty file mode 600 so tee does not leave
		// the mode to the umask, then the content on stdin.
		if len(plan.Commands) != 3 || plan.Commands[2].Stdin != pastedKey+"\n" {
			t.Fatalf("commands = %+v", plan.Commands)
		}
		if got := plan.Commands[1].String(); !strings.HasSuffix(got,
			"install -m 600 /dev/null "+AuthorizedKeysPathFor(model.Users[0].Home)) {
			t.Errorf("the file is not created mode 600 first: %q", got)
		}
	})

	t.Run("an existing file", func(t *testing.T) {
		model, home := keysHome(t)
		mustMkdir(t, filepath.Join(home, ".ssh"))
		mustWrite(t, filepath.Join(home, ".ssh", "authorized_keys"), victimKeys)
		model.Users = LoadAuthorizedKeys(model.Users,
			func(path string) (string, error) {
				return backend.readKeys(t.Context(), model.Users[0])
			})
		if len(model.Users[0].Keys) != 1 {
			t.Fatalf("read %d keys from the account's own file",
				len(model.Users[0].Keys))
		}

		// An existing file is written in place by tee, with nothing that
		// truncates or unlinks it first.
		add, err := backend.BuildAddAuthorizedKey(model, "deploy", secondKey)
		if err != nil {
			t.Fatalf("BuildAddAuthorizedKey: %v", err)
		}
		assertRunAsAccount(t, "deploy", add.Commands)
		if len(add.Commands) != 2 {
			t.Errorf("an existing file was planned as %d commands: %+v",
				len(add.Commands), add.Commands)
		}

		remove, err := backend.BuildRemoveAuthorizedKey(model, "deploy",
			model.Users[0].Keys[0].Fingerprint)
		if err != nil {
			t.Fatalf("BuildRemoveAuthorizedKey: %v", err)
		}
		assertRunAsAccount(t, "deploy", remove.Commands)
		if remove.TempPath != "" {
			t.Errorf("a removal staged %s, which the account cannot read",
				remove.TempPath)
		}
	})
}

// assertRunAsAccount checks that every command goes through runuser as the
// account.
func assertRunAsAccount(t *testing.T, name string, commands []ssh.Command) {
	t.Helper()
	for _, cmd := range commands {
		if len(cmd.Argv) < 5 || cmd.Argv[0] != RunAs || cmd.Argv[1] != "-u" ||
			cmd.Argv[2] != name || cmd.Argv[3] != "--" {
			t.Errorf("%q does not run as %s", cmd.String(), name)
		}
	}
}
