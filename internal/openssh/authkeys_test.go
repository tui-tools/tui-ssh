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

// demoUser is the account the command builders are exercised against.
var demoUser = ssh.User{
	Name: "deploy", Group: "deploy", Home: "/home/deploy",
	KeysPath: "/home/deploy/.ssh/authorized_keys",
}

func TestBuildCreateSSHDir(t *testing.T) {
	cmd, err := BuildCreateSSHDir(demoUser)
	if err != nil {
		t.Fatalf("BuildCreateSSHDir: %v", err)
	}
	want := "install -d -m 700 -o deploy -g deploy /home/deploy/.ssh"
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	if !cmd.Destructive {
		t.Errorf("creating a directory as root is a change worth confirming")
	}
}

func TestBuildInstallAuthorizedKeys(t *testing.T) {
	cmd, err := BuildInstallAuthorizedKeys("/tmp/tui-ssh-42/authorized_keys", demoUser)
	if err != nil {
		t.Fatalf("BuildInstallAuthorizedKeys: %v", err)
	}
	want := "install -m 600 -o deploy -g deploy /tmp/tui-ssh-42/authorized_keys " +
		"/home/deploy/.ssh/authorized_keys"
	if got := cmd.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}
	if !cmd.Destructive {
		t.Errorf("overwriting somebody's authorized_keys is a destructive change")
	}

	for _, bad := range []string{"", "relative/path", "/tmp/x;reboot", "/tmp/a b"} {
		if _, err := BuildInstallAuthorizedKeys(bad, demoUser); err == nil {
			t.Errorf("BuildInstallAuthorizedKeys accepted the staging path %q", bad)
		}
	}
}

// TestKeyCommandsRefuseAnAccountTheyCannotTrust: the account name and its home
// are read out of /etc/passwd and then land in an argv that runs as root, so
// they are checked here rather than trusted for having come from a file.
func TestKeyCommandsRefuseAnAccountTheyCannotTrust(t *testing.T) {
	bad := []ssh.User{
		{Name: "", Home: "/home/x"},
		{Name: "de ploy", Home: "/home/deploy"},
		{Name: "deploy; reboot", Home: "/home/deploy"},
		{Name: "deploy", Home: "relative"},
		{Name: "deploy", Home: "/home/deploy/../../etc"},
		{Name: "deploy", Home: "/home/de ploy"},
		{Name: "deploy", Home: "/"},
		{Name: "deploy", Home: "/home/deploy", Group: "deploy; reboot"},
	}
	for _, user := range bad {
		if err := CheckUser(user); err == nil {
			t.Errorf("CheckUser accepted %+v", user)
		}
		if _, err := BuildCreateSSHDir(user); err == nil {
			t.Errorf("BuildCreateSSHDir accepted %+v", user)
		}
		if _, err := BuildInstallAuthorizedKeys("/tmp/tui-ssh-1/authorized_keys",
			user); err == nil {
			t.Errorf("BuildInstallAuthorizedKeys accepted %+v", user)
		}
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
