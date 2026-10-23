package openssh

import (
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// TestParseAuthLogCountsRefusals reads a journal captured from OpenSSH 9.6p1
// on Ubuntu 24.04 (addresses rewritten to the documentation range). With
// PasswordAuthentication no, a refused attempt leaves only "Connection closed
// by authenticating user ... [preauth]": those used to go uncounted.
//
// What the capture holds, in order: a wrong password with passwords still on
// (a "Failed password" and then its closing line), then with passwords off a
// password client for ana, an unknown key for ana, an unknown user, a password
// client for deploy, two accepted keys, three wrong passwords with passwords
// back on (one "Failed password", then its closing line), a client that sent
// no password at all, seven unknown keys (maximum authentication attempts),
// and two password clients that were refused for ana and root.
func TestParseAuthLogCountsRefusals(t *testing.T) {
	log := ParseAuthLog(fixture(t, "journal-refusals-openssh96.txt"), ssh.Window24h, "journalctl")

	if log.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", log.Accepted)
	}
	// Two "Failed password", one "maximum authentication attempts" and six
	// refusals that left nothing but the closing line. The two closing lines
	// that follow a "Failed password" on the same connection are not counted
	// again.
	if log.Failed != 9 {
		t.Errorf("failed = %d, want 9", log.Failed)
	}
	if log.InvalidUser != 1 {
		t.Errorf("invalid user = %d, want 1", log.InvalidUser)
	}
	users := map[string]int{}
	for _, count := range log.TopUsers {
		users[count.Name] = count.Count
	}
	// ana: 2 failed passwords, 1 max-auth, 4 refusals. bob is the invalid user.
	want := map[string]int{"ana": 7, "deploy": 1, "root": 1, "bob": 1}
	for name, n := range want {
		if users[name] != n {
			t.Errorf("failures for %s = %d, want %d (top users %v)", name, users[name], n, log.TopUsers)
		}
	}
	if len(log.TopIPs) != 1 || log.TopIPs[0].Name != "198.51.100.20" || log.TopIPs[0].Count != 10 {
		t.Errorf("top addresses = %v, want 198.51.100.20 x10", log.TopIPs)
	}
	refusals := 0
	for _, event := range log.Events {
		if event.Kind == ssh.AuthFailed && event.Method == "" && event.IP == "198.51.100.20" &&
			event.User != "" {
			refusals++
		}
	}
	// The six refusals plus the max-auth line, which names no method either.
	if refusals != 7 {
		t.Errorf("failed events without a method = %d, want 7", refusals)
	}
}

// TestRefusalFormsAndDeduplication covers the other two closing lines OpenSSH
// writes for an account that never authenticated, and a client that sends a
// disconnect after a failure: one attempt is one count however many lines it
// leaves.
func TestRefusalFormsAndDeduplication(t *testing.T) {
	journal := `2026-10-23T10:00:00+00:00 host sshd[10]: Received disconnect from 203.0.113.7 port 40000:11: Bye Bye [preauth]
2026-10-23T10:00:00+00:00 host sshd[10]: Disconnected from authenticating user root 203.0.113.7 port 40000 [preauth]
2026-10-23T10:00:01+00:00 host sshd[11]: Connection reset by authenticating user admin 203.0.113.8 port 40001 [preauth]
2026-10-23T10:00:02+00:00 host sshd[12]: Failed password for ana from 2001:db8::7 port 40002 ssh2
2026-10-23T10:00:02+00:00 host sshd[12]: Received disconnect from 2001:db8::7 port 40002:11: Bye Bye [preauth]
2026-10-23T10:00:02+00:00 host sshd[12]: Disconnected from authenticating user ana 2001:db8::7 port 40002 [preauth]
2026-10-23T10:00:03+00:00 host sshd[13]: Connection closed by 203.0.113.9 port 40003 [preauth]
2026-10-23T10:00:04+00:00 host sshd[14]: Disconnected from user ana 192.0.2.10 port 40004
2026-10-23T10:00:05+00:00 host sshd[15]: Connection closed by authenticating user ana 192.0.2.11 port 40005 [preauth]
2026-10-23T10:00:05+00:00 host sshd[15]: Connection closed by authenticating user ana 192.0.2.11 port 40005 [preauth]
`
	log := ParseAuthLog(journal, ssh.Window24h, "journalctl")
	// root's disconnect, admin's reset, ana's failed password (its disconnect
	// is the same connection) and the 192.0.2.11 refusal (logged twice, one
	// connection). The scanner that never named an account and the logout of
	// an accepted session are not attempts on an account.
	if log.Failed != 4 {
		t.Errorf("failed = %d, want 4; events %+v", log.Failed, log.Events)
	}
	byUser := map[string]string{}
	for _, event := range log.Events {
		byUser[event.User] = event.IP
	}
	if byUser["root"] != "203.0.113.7" || byUser["admin"] != "203.0.113.8" ||
		byUser["ana"] == "" {
		t.Errorf("users and addresses = %v", byUser)
	}
}
