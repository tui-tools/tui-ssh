package openssh

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The sample keys, with the fingerprint, type and size `ssh-keygen -lf` prints
// for each. They were generated for this test and their private halves thrown
// away; the expected values are ssh-keygen's own output, so this table is what
// keeps the fingerprint this tool computes tied to the one OpenSSH computes.
var keyFixtures = []struct {
	name        string
	line        string
	fingerprint string
	keyType     string
	bits        int
	comment     string
}{
	{
		name: "ed25519",
		line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVu7l48AcDeT36Odle6Mnflh5Bs" +
			"VHir2huMQEf+qt4Z deploy@laptop",
		fingerprint: "SHA256:E9pkwHTZW2lwoLIfOfqChZirK7c79yjmU3iEnp08lZM",
		keyType:     "ED25519",
		bits:        256,
		comment:     "deploy@laptop",
	},
	{
		name: "rsa",
		line: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC70Q+c5ix9Nvo9wgzlCVc9Xxvth4" +
			"LhYz/ZDelU8UFfXMWvcZvF+EXYoaJ74qvngnMbny7j2irScSeCj3nxF2aJ5YdO1J2fe" +
			"EXf+46CJK9Yy4vIvuoAE7uALqlN0LIrbQn6EMCMwk5vssPib2aRMgvr4WIAvtJPVzKt" +
			"1LnrmAGfWHU8q/1Wj8e98bnuwSez5b4+p+xx9eSP1GnsSkoJuP/kN2BuNGKRVVV/tjg" +
			"9N49uQ2w6RVW1cyqTcMYwa0WyfrmowWBxy5fqmJHYSYmytjvjDncuNvDTZYOPjqqQrw" +
			"s/YEMVUnhQ2ifIaOL5Dlgec0yvaCO4HmAXxm2sgq0Cs5sgTdnqn4tRE120JtXcclnfZ" +
			"se+ANjjQ/swX8AsZyp/yEvahGQKqpPCeW2O2+ZfEtJIswCNtHYgAw4IOR0sNVh/OxX1" +
			"TGwUp9ng9UgucUB/SxAZN6vQtRwklPJe395rWyI7gDVqwRsmOgrIbHsOeBFZPkFKGB8" +
			"b3rmQ5NYl9MYOdAc= ana@workstation",
		fingerprint: "SHA256:NflX/MsGKP0XzUnmnIAsmQv8ztv93ZYKTlGTC9Sl06c",
		keyType:     "RSA",
		bits:        3072,
		comment:     "ana@workstation",
	},
	{
		name: "ecdsa",
		line: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyN" +
			"TYAAABBBKv9x7BOXVECTBDT4+5PkTyBqQFxEBU+TCa8iA3Cc/9Qx5JPcdR7D6zuYuoK" +
			"KzujJevksu1GAVBMTrwXGIgL2+c= ci@runner",
		fingerprint: "SHA256:dcB/HBd6P9YYbbodUCoKdxkvEOQ2qV7w80mxT0ceYKY",
		keyType:     "ECDSA",
		bits:        256,
		comment:     "ci@runner",
	},
}

// TestParseAuthorizedKeyMatchesSshKeygen is the load-bearing one: a key is
// identified by its fingerprint everywhere in this tool, and a fingerprint that
// did not match ssh-keygen's would name the wrong key on the screen and remove
// the wrong line from the file.
func TestParseAuthorizedKeyMatchesSshKeygen(t *testing.T) {
	for _, fixture := range keyFixtures {
		key, ok := ParseAuthorizedKey(fixture.line)
		if !ok {
			t.Fatalf("%s: the line did not parse as a public key", fixture.name)
		}
		if key.Fingerprint != fixture.fingerprint {
			t.Errorf("%s: fingerprint %q, want ssh-keygen's %q",
				fixture.name, key.Fingerprint, fixture.fingerprint)
		}
		if key.Type != fixture.keyType {
			t.Errorf("%s: type %q, want %q", fixture.name, key.Type, fixture.keyType)
		}
		if key.Bits != fixture.bits {
			t.Errorf("%s: %d bits, want %d", fixture.name, key.Bits, fixture.bits)
		}
		if key.Comment != fixture.comment {
			t.Errorf("%s: comment %q, want %q",
				fixture.name, key.Comment, fixture.comment)
		}
		if key.Options != "" {
			t.Errorf("%s: read options %q off a plain key", fixture.name, key.Options)
		}
	}
}

func TestParseAuthorizedKeyReadsOptions(t *testing.T) {
	// A restricted key: the options come first and nothing marks where they
	// end, so the parser finds the key by decoding it rather than by counting
	// fields.
	line := `from="203.0.113.0/24",no-pty ` + keyFixtures[0].line
	key, ok := ParseAuthorizedKey(line)
	if !ok {
		t.Fatalf("a key with options did not parse")
	}
	if key.Options != `from="203.0.113.0/24",no-pty` {
		t.Errorf("options = %q", key.Options)
	}
	if key.Fingerprint != keyFixtures[0].fingerprint {
		t.Errorf("the options changed the fingerprint: %q", key.Fingerprint)
	}

	for _, bad := range []string{
		"", "   ", "# a comment", "ssh-ed25519", "ssh-ed25519 not-base64",
		// Base64 that decodes but is not a key of the type it claims to be.
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
		"ssh-rsa " + strings.SplitN(keyFixtures[0].line, " ", 3)[1],
	} {
		if _, ok := ParseAuthorizedKey(bad); ok {
			t.Errorf("ParseAuthorizedKey accepted %q", bad)
		}
	}
}

func TestParseAuthorizedKeysNumbersTheLines(t *testing.T) {
	raw := "# deploy's keys\n\n" + keyFixtures[0].line + "\n" +
		keyFixtures[2].line + "\n"
	keys := ParseAuthorizedKeys(raw)
	if len(keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(keys))
	}
	if keys[0].Line != 3 || keys[1].Line != 4 {
		t.Errorf("lines = %d, %d; want 3, 4", keys[0].Line, keys[1].Line)
	}
}

func TestCheckPublicKey(t *testing.T) {
	key, err := CheckPublicKey("  " + keyFixtures[0].line + "  \n")
	if err != nil {
		t.Fatalf("CheckPublicKey refused a good key: %v", err)
	}
	if key.Fingerprint != keyFixtures[0].fingerprint {
		t.Errorf("fingerprint = %q", key.Fingerprint)
	}

	bad := map[string]string{
		"empty":   "",
		"garbage": "hello",
		// A private key pasted by mistake is the one wrong paste worth naming.
		"private key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb\n" +
			"-----END OPENSSH PRIVATE KEY-----",
		"two keys": keyFixtures[0].line + "\n" + keyFixtures[2].line,
		// Options in a paste would write a forced command into somebody's
		// account without ever showing it as what it is.
		"options": `command="/bin/sh" ` + keyFixtures[0].line,
	}
	for name, value := range bad {
		if _, err := CheckPublicKey(value); err == nil {
			t.Errorf("CheckPublicKey accepted %s", name)
		}
	}
}

func TestRenderAuthorizedKeysWith(t *testing.T) {
	before := "# deploy's keys\n" + keyFixtures[0].line + "\n"
	key, err := CheckPublicKey(keyFixtures[2].line)
	if err != nil {
		t.Fatalf("CheckPublicKey: %v", err)
	}

	after, err := RenderAuthorizedKeysWith(before, key)
	if err != nil {
		t.Fatalf("RenderAuthorizedKeysWith: %v", err)
	}
	// The file is not one tui-ssh owns: everything that was in it is still in
	// it, in the same order, comment included.
	if !strings.HasPrefix(after, before) {
		t.Errorf("the existing file was not preserved:\n%s", after)
	}
	if !strings.HasSuffix(after, keyFixtures[2].line+"\n") {
		t.Errorf("the new key is not the last line:\n%s", after)
	}
	if len(ParseAuthorizedKeys(after)) != 2 {
		t.Errorf("the result carries %d keys, want 2", len(ParseAuthorizedKeys(after)))
	}

	// A key that is already there is refused rather than written twice.
	if _, err := RenderAuthorizedKeysWith(after, key); err == nil {
		t.Errorf("the same key was appended a second time")
	}

	// A file with no trailing newline does not swallow the key that follows it.
	joined, err := RenderAuthorizedKeysWith(keyFixtures[0].line, key)
	if err != nil {
		t.Fatalf("RenderAuthorizedKeysWith: %v", err)
	}
	if len(ParseAuthorizedKeys(joined)) != 2 {
		t.Errorf("a file with no trailing newline lost a key:\n%s", joined)
	}
}

func TestRenderAuthorizedKeysWithout(t *testing.T) {
	before := "# deploy's keys\n" + keyFixtures[0].line + "\n" +
		keyFixtures[2].line + "\n"

	after, err := RenderAuthorizedKeysWithout(before, keyFixtures[0].fingerprint)
	if err != nil {
		t.Fatalf("RenderAuthorizedKeysWithout: %v", err)
	}
	if strings.Contains(after, keyFixtures[0].fingerprint) ||
		len(ParseAuthorizedKeys(after)) != 1 {
		t.Errorf("the key was not removed:\n%s", after)
	}
	if !strings.Contains(after, "# deploy's keys") {
		t.Errorf("a rewrite dropped a comment that was not ours to drop:\n%s", after)
	}
	if !strings.Contains(after, keyFixtures[2].line) {
		t.Errorf("the other key was lost:\n%s", after)
	}

	// Removing the last key leaves an empty file rather than deleting one.
	empty, err := RenderAuthorizedKeysWithout(keyFixtures[0].line+"\n",
		keyFixtures[0].fingerprint)
	if err != nil {
		t.Fatalf("RenderAuthorizedKeysWithout: %v", err)
	}
	if empty != "" {
		t.Errorf("removing the only key left %q", empty)
	}

	// A fingerprint that is not in the file, and one that is not a fingerprint
	// at all, both stop before anything is staged.
	for _, bad := range []string{
		"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"", "not-a-fingerprint", "SHA256:../../etc/passwd",
	} {
		if _, err := RenderAuthorizedKeysWithout(before, bad); err == nil {
			t.Errorf("RenderAuthorizedKeysWithout accepted %q", bad)
		}
	}
}

// deployHome is the home of the account the command builders are exercised
// against.
const deployHome = "/home/deploy"

// demoUser is the account the command builders are exercised against.
var demoUser = ssh.User{
	Name: "deploy", Group: "deploy", Home: "/home/deploy",
	KeysPath: AuthorizedKeysPathFor(deployHome),
}

func TestBuildCreateSSHDir(t *testing.T) {
	cmd, err := BuildCreateSSHDir(demoUser, ProgramNames)
	if err != nil {
		t.Fatalf("BuildCreateSSHDir: %v", err)
	}
	// Run as the account: a ~/.ssh the account pointed somewhere else cannot
	// take root's chmod or chown with it.
	want := "runuser -u deploy -- install -d -m 700 " + SSHDirFor(deployHome)
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	if !cmd.Destructive {
		t.Errorf("creating a directory in somebody's home is a change worth confirming")
	}
}

func TestBuildInstallAuthorizedKeys(t *testing.T) {
	const content = "ssh-ed25519 AAAA deploy@laptop\n"
	cmd, err := BuildInstallAuthorizedKeys(content, demoUser, ProgramNames)
	if err != nil {
		t.Fatalf("BuildInstallAuthorizedKeys: %v", err)
	}
	// The content travels on stdin and tee writes it from the descriptor it
	// was handed: the account runs the write and must not be able to read
	// this tool's private staging directory, and it cannot reopen /dev/stdin
	// either, because the pipe belongs to root (or to the admin behind sudo).
	want := "runuser -u deploy -- tee " + AuthorizedKeysPathFor(deployHome)
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	for _, arg := range cmd.Argv {
		if arg == "/dev/stdin" || arg == "/proc/self/fd/0" {
			t.Errorf("%q makes the account reopen a pipe it does not own",
				cmd.String())
		}
	}
	if cmd.Stdin != content {
		t.Errorf("stdin = %q, want %q", cmd.Stdin, content)
	}
	if !cmd.Destructive {
		t.Errorf("overwriting somebody's authorized_keys is a destructive change")
	}
	for _, arg := range cmd.Argv {
		if arg == "-o" || arg == "-g" {
			t.Errorf("%q still sets an owner", cmd.String())
		}
	}
}

// TestKeyCommandsUseTheResolvedPrograms keeps the preview honest: runuser looks
// its command up on PATH, so the real backend hands it the absolute path it
// resolved, and the argv shows that path.
func TestKeyCommandsUseTheResolvedPrograms(t *testing.T) {
	programs := Programs{Install: "/usr/bin/install", Tee: "/usr/bin/tee",
		Cat: "/usr/bin/cat"}
	cmd, err := BuildInstallAuthorizedKeys("", demoUser, programs)
	if err != nil {
		t.Fatalf("BuildInstallAuthorizedKeys: %v", err)
	}
	want := "runuser -u deploy -- /usr/bin/tee " + AuthorizedKeysPathFor(deployHome)
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	create, err := BuildCreateAuthorizedKeys(demoUser, programs)
	if err != nil {
		t.Fatalf("BuildCreateAuthorizedKeys: %v", err)
	}
	want = "runuser -u deploy -- /usr/bin/install -m 600 /dev/null " +
		AuthorizedKeysPathFor(deployHome)
	if got := create.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	read, err := BuildReadAuthorizedKeys(demoUser, programs)
	if err != nil {
		t.Fatalf("BuildReadAuthorizedKeys: %v", err)
	}
	want = "runuser -u deploy -- /usr/bin/cat -- " + AuthorizedKeysPathFor(deployHome)
	if got := strings.Join(read, " "); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
}

// TestKeyCommandsRefuseAnAccountTheyCannotTrust: the account name and its home
// are read out of /etc/passwd and then land in an argv that runs privileged, so
// they are checked here rather than trusted for having come from a file.
func TestKeyCommandsRefuseAnAccountTheyCannotTrust(t *testing.T) {
	bad := []ssh.User{
		{Name: "", Home: "/home/x"},
		{Name: "de ploy", Home: "/home/deploy"},
		{Name: "deploy; reboot", Home: "/home/deploy"},
		{Name: "-deploy", Home: "/home/deploy"},
		{Name: "deploy", Home: "relative"},
		{Name: "deploy", Home: deployHome + "/../../etc"},
		{Name: "deploy", Home: "/home/de ploy"},
		{Name: "deploy", Home: "/"},
		{Name: "deploy", Home: "/home/deploy", Group: "deploy; reboot"},
	}
	for _, user := range bad {
		if err := CheckUser(user); err == nil {
			t.Errorf("CheckUser accepted %+v", user)
		}
		if _, err := BuildCreateSSHDir(user, ProgramNames); err == nil {
			t.Errorf("BuildCreateSSHDir accepted %+v", user)
		}
		if _, err := BuildInstallAuthorizedKeys("", user, ProgramNames); err == nil {
			t.Errorf("BuildInstallAuthorizedKeys accepted %+v", user)
		}
		if _, err := BuildReadAuthorizedKeys(user, ProgramNames); err == nil {
			t.Errorf("BuildReadAuthorizedKeys accepted %+v", user)
		}
	}
}

// TestCheckKeyPaths covers the refusals: a name that could send a read or a
// write somewhere other than the account's own ~/.ssh.
func TestCheckKeyPaths(t *testing.T) {
	dir := func(uid int) PathState { return PathState{Kind: KindDir, UID: uid} }
	file := func(uid int) PathState { return PathState{Kind: KindFile, UID: uid} }
	missing := PathState{Kind: KindMissing}
	link := PathState{Kind: KindSymlink, UID: 1000}
	deploy := demoUser
	deploy.UID = 1000
	root := ssh.User{Name: "root", Home: "/root", UID: 0}

	tests := []struct {
		name      string
		user      ssh.User
		dir, file PathState
		want      string // empty: accepted
	}{
		{name: "nothing there yet", user: deploy, dir: missing, file: missing},
		{name: "a directory, no file", user: deploy, dir: dir(1000), file: missing},
		{name: "both the account's", user: deploy, dir: dir(1000), file: file(1000)},
		{name: "root's own keys", user: root, dir: dir(0), file: file(0)},
		{name: "symlinked file", user: deploy, dir: dir(1000), file: link,
			want: "/home/deploy/.ssh/authorized_keys is a symbolic link"},
		{name: "symlinked directory", user: deploy, dir: link, file: missing,
			want: "/home/deploy/.ssh is a symbolic link"},
		{name: "directory owned by another account", user: deploy, dir: dir(1001),
			file: missing,
			want: "/home/deploy/.ssh belongs to uid 1001, not to deploy (uid 1000)"},
		{name: "file owned by root", user: deploy, dir: dir(1000), file: file(0),
			want: "/home/deploy/.ssh/authorized_keys belongs to uid 0"},
		{name: "a file where the directory goes", user: deploy, dir: file(1000),
			file: missing, want: "/home/deploy/.ssh is not a directory"},
		{name: "a socket where the file goes", user: deploy, dir: dir(1000),
			file: PathState{Kind: KindOther, UID: 1000},
			want: "/home/deploy/.ssh/authorized_keys is not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckKeyPaths(tc.user, tc.dir, tc.file)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && err == nil:
				t.Errorf("accepted, want a refusal containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestParseStat(t *testing.T) {
	tests := map[string]PathState{
		"1000 directory":          {Kind: KindDir, UID: 1000},
		"0 regular file":          {Kind: KindFile, UID: 0},
		"1000 regular empty file": {Kind: KindFile, UID: 1000},
		"1000 symbolic link":      {Kind: KindSymlink, UID: 1000},
		"1000 socket":             {Kind: KindOther, UID: 1000},
	}
	for out, want := range tests {
		got, err := ParseStat(out + "\n")
		if err != nil || got != want {
			t.Errorf("ParseStat(%q) = %+v, %v; want %+v", out, got, err, want)
		}
	}
	if _, err := ParseStat("stat: cannot statx"); err == nil {
		t.Error("ParseStat accepted an error message")
	}
}

func TestBuildFingerprintKey(t *testing.T) {
	cmd, err := BuildFingerprintKey("/tmp/tui-ssh-42/authorized_keys")
	if err != nil {
		t.Fatalf("BuildFingerprintKey: %v", err)
	}
	if got := cmd.String(); got != "ssh-keygen -l -f /tmp/tui-ssh-42/authorized_keys" {
		t.Errorf("argv %q", got)
	}
	if cmd.Destructive {
		t.Errorf("reading a key is a read and must not be marked destructive")
	}
	if _, err := BuildFingerprintKey("/etc/shadow; reboot"); err == nil {
		t.Errorf("BuildFingerprintKey accepted a path that is not a staging path")
	}
}

func TestAuthorizedKeyLabel(t *testing.T) {
	key, _ := ParseAuthorizedKey(keyFixtures[0].line)
	want := keyFixtures[0].fingerprint + " deploy@laptop (ED25519)"
	if got := key.Label(); got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}
