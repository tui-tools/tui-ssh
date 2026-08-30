package openssh

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// TestVerdicts pins the judgement table. Every row here is an opinion this
// tool states out loud, so a change to one is a change a reviewer should see
// in a diff rather than discover on a screen.
func TestVerdicts(t *testing.T) {
	tests := []struct {
		key, value string
		want       ssh.Verdict
	}{
		{"PermitRootLogin", "no", ssh.VerdictOK},
		{"PermitRootLogin", "prohibit-password", ssh.VerdictOK},
		{"PermitRootLogin", "forced-commands-only", ssh.VerdictOK},
		{"PermitRootLogin", "yes", ssh.VerdictRisk},
		{"PasswordAuthentication", "no", ssh.VerdictOK},
		{"PasswordAuthentication", "yes", ssh.VerdictRisk},
		{"PubkeyAuthentication", "yes", ssh.VerdictOK},
		{"PubkeyAuthentication", "no", ssh.VerdictWarn},
		{"PermitEmptyPasswords", "no", ssh.VerdictOK},
		{"PermitEmptyPasswords", "yes", ssh.VerdictRisk},
		{"MaxAuthTries", "3", ssh.VerdictOK},
		{"MaxAuthTries", "6", ssh.VerdictWarn},
		{"MaxAuthTries", "20", ssh.VerdictRisk},
		{"LoginGraceTime", "30", ssh.VerdictOK},
		{"LoginGraceTime", "2m", ssh.VerdictWarn},
		{"LoginGraceTime", "0", ssh.VerdictRisk},
		{"UsePAM", "yes", ssh.VerdictOK},
		{"UsePAM", "no", ssh.VerdictWarn},
		{"X11Forwarding", "no", ssh.VerdictOK},
		{"X11Forwarding", "yes", ssh.VerdictWarn},
		{"AllowTcpForwarding", "no", ssh.VerdictOK},
		{"AllowTcpForwarding", "yes", ssh.VerdictNone},
		{"ClientAliveInterval", "300", ssh.VerdictOK},
		{"ClientAliveInterval", "0", ssh.VerdictWarn},
		{"AllowUsers", "ana deploy", ssh.VerdictOK},
		// A keyword this tool has no opinion about stays unjudged rather than
		// being painted a colour it did not earn.
		{"Subsystem", "sftp /usr/libexec/openssh/sftp-server", ssh.VerdictNone},
		{"MaxSessions", "10", ssh.VerdictNone},
	}
	for _, test := range tests {
		verdict, note := verdictFor(test.key, test.value)
		if verdict != test.want {
			t.Errorf("%s=%s → %q, want %q", test.key, test.value, verdict, test.want)
		}
		if (verdict == ssh.VerdictRisk || verdict == ssh.VerdictWarn) && note == "" {
			t.Errorf("%s=%s is a finding with no explanation",
				test.key, test.value)
		}
	}
}

// TestRenamedKeywordIsJudgedUnderBothSpellings: a machine that writes the
// pre-8.7 name must get the same verdict as one that writes the new one.
func TestRenamedKeywordIsJudgedUnderBothSpellings(t *testing.T) {
	for _, key := range []string{KbdInteractiveKey, ChallengeResponseKey} {
		if verdict, _ := verdictFor(key, "no"); verdict != ssh.VerdictOK {
			t.Errorf("%s=no → %q", key, verdict)
		}
		if verdict, _ := verdictFor(key, "yes"); verdict != ssh.VerdictWarn {
			t.Errorf("%s=yes → %q", key, verdict)
		}
	}
	// And both sort to the same place, so the row does not move when a machine
	// happens to use the old name.
	settings := Order([]ssh.Setting{
		{Key: "Subsystem"}, {Key: ChallengeResponseKey}, {Key: "PermitRootLogin"},
	})
	if settings[0].Key != "PermitRootLogin" || settings[1].Key != ChallengeResponseKey {
		t.Errorf("order = %q, %q", settings[0].Key, settings[1].Key)
	}
}

func TestWeakAlgorithmsAreNamed(t *testing.T) {
	tests := []struct {
		key, value string
		want       ssh.Verdict
		names      string
	}{
		{"Ciphers", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
			ssh.VerdictOK, ""},
		{"Ciphers", "aes256-ctr,aes128-cbc", ssh.VerdictRisk, "aes128-cbc"},
		{"Ciphers", "3des-cbc", ssh.VerdictRisk, "3des-cbc"},
		{"KexAlgorithms", "curve25519-sha256,diffie-hellman-group14-sha1",
			ssh.VerdictRisk, "diffie-hellman-group14-sha1"},
		{"KexAlgorithms", "curve25519-sha256,ecdh-sha2-nistp256", ssh.VerdictOK, ""},
		{"MACs", "hmac-sha2-256-etm@openssh.com", ssh.VerdictOK, ""},
		{"MACs", "hmac-sha2-256-etm@openssh.com,hmac-sha1", ssh.VerdictRisk, "hmac-sha1"},
		// A list that subtracts from the default cannot add anything weak
		// back, so it is not a finding.
		{"Ciphers", "-aes128-cbc", ssh.VerdictOK, ""},
		{"Ciphers", "+aes128-cbc", ssh.VerdictRisk, "aes128-cbc"},
	}
	for _, test := range tests {
		verdict, note := verdictFor(test.key, test.value)
		if verdict != test.want {
			t.Errorf("%s=%s → %q, want %q", test.key, test.value, verdict, test.want)
		}
		if test.names != "" && !strings.Contains(note, test.names) {
			t.Errorf("%s=%s: the note does not name %q: %q",
				test.key, test.value, test.names, note)
		}
	}
}

func TestListenAddressOnLoopbackIsWorthSaying(t *testing.T) {
	verdict, note := verdictFor("ListenAddress", "127.0.0.1")
	if verdict != ssh.VerdictOK || !strings.Contains(note, "loopback") {
		t.Errorf("loopback ListenAddress → %q, %q", verdict, note)
	}
	if verdict, _ := verdictFor("ListenAddress", "0.0.0.0"); verdict != ssh.VerdictNone {
		t.Errorf("a wildcard ListenAddress is not a finding on its own")
	}
	// The port form is still an address on the loopback.
	if verdict, _ := verdictFor("ListenAddress", "127.0.0.1:22"); verdict != ssh.VerdictOK {
		t.Errorf("127.0.0.1:22 was not recognised as the loopback")
	}
}

func TestJudgeHostKeys(t *testing.T) {
	keys := JudgeHostKeys([]ssh.HostKey{
		{Type: "ED25519", Bits: 256},
		{Type: "RSA", Bits: 3072},
		{Type: "RSA", Bits: 2048},
		{Type: "RSA", Bits: 1024},
		{Type: "DSA", Bits: 1024},
		{Type: "ECDSA", Bits: 256},
	})
	want := []ssh.Verdict{
		ssh.VerdictOK, ssh.VerdictOK, ssh.VerdictWarn,
		ssh.VerdictRisk, ssh.VerdictRisk, ssh.VerdictNone,
	}
	for i, key := range keys {
		if key.Verdict != want[i] {
			t.Errorf("%s %d bits → %q, want %q",
				key.Type, key.Bits, key.Verdict, want[i])
		}
	}
}

func TestFindingsAreWorstFirst(t *testing.T) {
	model := ssh.Model{Settings: Judge([]ssh.Setting{
		{Key: "X11Forwarding", Value: "yes"},
		{Key: "PasswordAuthentication", Value: "yes"},
		{Key: "PubkeyAuthentication", Value: "yes"},
	})}
	findings := model.Findings()
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want the two that are not ok", len(findings))
	}
	if findings[0].Key != "PasswordAuthentication" {
		t.Errorf("findings[0] = %q, want the risk first", findings[0].Key)
	}
}
