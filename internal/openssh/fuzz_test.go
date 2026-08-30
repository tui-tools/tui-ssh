package openssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// This package is where output tui-ssh did not write becomes the model the
// screens draw and the values the commands are built from: `sshd -T`, an
// sshd_config and everything it includes, `loginctl`, `ss`, `ssh-keygen -lf`
// and the server's own authentication lines. `go test` runs the seeds below on
// every commit, and `go test -run=^$ -fuzz=FuzzParseEffective ./internal/openssh`
// explores past them locally — see tui-kit/templates/FUZZING.md for the family
// rule.
//
// The seeds are the captured fixtures the table tests use, so the corpus starts
// on the real line shapes and mutates from there instead of guessing them.

// seed adds every named testdata file to the corpus, plus the shapes a real
// capture never has: nothing, blank lines, a lone separator, a truncated line.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(string(raw))
	}
	f.Add("")
	f.Add("\n\n\n")
	f.Add("=")
	f.Add(":")
	f.Add("#")
	f.Add("Include ")
}

// checkKeyword asserts what every caller of a parsed directive may assume: a
// keyword it can look up and print, never a blank and never a whole line.
func checkKeyword(t *testing.T, key string) {
	t.Helper()
	if key == "" {
		t.Fatalf("blank keyword")
	}
	if strings.ContainsAny(key, " \t\r\n#") {
		t.Fatalf("keyword is not a bare word: %q", key)
	}
}

// checkPort asserts a parsed port is one a machine could actually listen on.
// Anything else means the field it came from was not a port at all.
func checkPort(t *testing.T, port int) {
	t.Helper()
	if port < 0 || port > 65535 {
		t.Fatalf("port outside the range a socket can carry: %d", port)
	}
}

func FuzzParseEffective(f *testing.F) {
	seed(f, "sshd-T.txt", "sshd-T-openssh105.txt")
	f.Fuzz(func(t *testing.T, out string) {
		seen := map[string]bool{}
		for _, setting := range ParseEffective(out) {
			checkKeyword(t, setting.Key)
			if !setting.Effective {
				t.Fatalf("%q came from `sshd -T` and is not marked effective", setting.Key)
			}
			// The table has one row per keyword: the repeats sshd prints for
			// port, hostkey and listenaddress are folded into one value.
			if seen[setting.Key] {
				t.Fatalf("keyword %q reported twice", setting.Key)
			}
			seen[setting.Key] = true
		}
	})
}

// FuzzParseConfigTree walks a tree in which every file is the fuzzed text and
// every Include pattern expands, which is the shape that stresses the include
// recursion rather than the line parser under it.
func FuzzParseConfigTree(f *testing.F) {
	seed(f, "sshd_config-include-first.txt", "sshd_config-include-last.txt",
		"50-distribution.conf.txt")
	f.Fuzz(func(t *testing.T, text string) {
		read := func(string) (string, error) { return text, nil }
		glob := func(pattern string) ([]string, error) {
			return []string{filepath.Join(filepath.Dir(pattern), "10-included.conf")}, nil
		}

		files := ParseConfigTree(read, glob, "/etc/ssh/sshd_config")
		if len(files) == 0 {
			t.Fatalf("the root file itself is missing from the tree")
		}
		paths := map[string]bool{}
		for _, file := range files {
			// A file is read once: the walk keeps a seen set so a file that
			// includes itself cannot loop.
			if paths[file.Path] {
				t.Fatalf("file %q walked twice", file.Path)
			}
			paths[file.Path] = true
			for i, line := range file.Lines {
				if line.Number != i+1 {
					t.Fatalf("%s line %d is numbered %d", file.Path, i+1, line.Number)
				}
				if line.Key != "" {
					checkKeyword(t, line.Key)
				}
			}
		}

		// The order decides which setting sshd actually uses, so what reads it
		// has to survive any file too.
		for key, sources := range SourcesFor(files) {
			if key != strings.ToLower(key) {
				t.Fatalf("source key is not lower case: %q", key)
			}
			if len(sources) == 0 {
				t.Fatalf("keyword %q maps to no source", key)
			}
		}
	})
}

func FuzzParseLoginctlSessions(f *testing.F) {
	seed(f, "loginctl-list-sessions.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, id := range ParseLoginctlSessions(out) {
			// The id goes into `loginctl terminate-session`, so nothing that
			// is not a session id may leave this parser.
			if !sessionRe.MatchString(id) {
				t.Fatalf("returned something that is not a session id: %q", id)
			}
		}
	})
}

func FuzzParseShowSession(f *testing.F) {
	seed(f, "loginctl-show-session-ssh.txt", "loginctl-show-session-desktop.txt")
	f.Fuzz(func(t *testing.T, out string) {
		session, ok := ParseShowSession(out)
		if !ok {
			if session != (ssh.Session{}) {
				t.Fatalf("rejected the block and still returned %#v", session)
			}
			return
		}
		if session.ID == "" {
			t.Fatalf("accepted a session with no id")
		}
		// Label() is what the sessions screen prints.
		_ = session.Label()
	})
}

func FuzzParseSSConnections(f *testing.F) {
	seed(f, "ss-established.txt")
	f.Fuzz(func(t *testing.T, out string) {
		sessions := ParseSSConnections(out)
		for _, session := range sessions {
			checkPort(t, session.RemotePort)
			checkPort(t, session.LocalPort)
			if strings.ContainsAny(session.RemoteIP, " \t\r\n") {
				t.Fatalf("peer address carries whitespace: %q", session.RemoteIP)
			}
			if session.Leader < 0 {
				t.Fatalf("negative pid: %d", session.Leader)
			}
			_ = session.Label()
		}
		// The merge is the other half of this read: it joins these rows to
		// whatever logind reported, and it runs on every refresh.
		_ = MergeSessions(nil, sessions, 22)
	})
}

func FuzzParseListeners(f *testing.F) {
	seed(f, "ss-listen.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, listener := range ParseListeners(out) {
			checkPort(t, listener.Port)
			if strings.ContainsAny(listener.Address, " \t\r\n") {
				t.Fatalf("listen address carries whitespace: %q", listener.Address)
			}
			if strings.ContainsAny(listener.Process, " \t\r\n") {
				t.Fatalf("process name carries whitespace: %q", listener.Process)
			}
			// String() is what the overview prints.
			_ = listener.String()
		}
	})
}

func FuzzParseProperties(f *testing.F) {
	seed(f, "systemctl-show-sshd.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for key := range ParseProperties(out) {
			if key == "" {
				t.Fatalf("property with no name")
			}
			if strings.ContainsAny(key, "\n=") || key != strings.TrimSpace(key) {
				t.Fatalf("property name is not a name: %q", key)
			}
		}
	})
}

// FuzzParseFingerprint is the one that matters most here: whatever it returns
// is the host key a reader is asked to compare against the one their client
// shows, so the shape of that answer has to hold for any input at all.
func FuzzParseFingerprint(f *testing.F) {
	seed(f, "ssh-keygen-ed25519.txt", "ssh-keygen-rsa.txt", "ssh-keygen-ecdsa.txt")
	f.Fuzz(func(t *testing.T, out string) {
		key, ok := ParseFingerprint("/etc/ssh/ssh_host_ed25519_key.pub", out)
		if !ok {
			if key != (ssh.HostKey{}) {
				t.Fatalf("rejected the line and still returned %#v", key)
			}
			return
		}
		if key.Fingerprint == "" {
			t.Fatalf("accepted a key with no fingerprint")
		}
		if strings.ContainsAny(key.Fingerprint, " \t\r\n") {
			t.Fatalf("fingerprint carries whitespace: %q", key.Fingerprint)
		}
		if strings.HasPrefix(key.Type, "(") || strings.HasSuffix(key.Type, ")") {
			t.Fatalf("key type still carries its parentheses: %q", key.Type)
		}
		if key.Bits < 0 {
			t.Fatalf("negative key size: %d", key.Bits)
		}
		if key.Path != "/etc/ssh/ssh_host_ed25519_key.pub" {
			t.Fatalf("the path was read from the output instead of the argument: %q", key.Path)
		}
	})
}

func FuzzParseAuthLog(f *testing.F) {
	seed(f, "auth-journal.txt")
	f.Fuzz(func(t *testing.T, out string) {
		log := ParseAuthLog(out, "the last 24 hours", "the journal")
		if log.Window != "the last 24 hours" || log.Source != "the journal" {
			t.Fatalf("the window and the source are carried through, not derived: %#v", log)
		}
		// Every counted line is also a listed event, and every listed event was
		// counted exactly once: the summary and the list are one read.
		if total := log.Accepted + log.Failed + log.InvalidUser; total != len(log.Events) {
			t.Fatalf("counted %d lines and listed %d", total, len(log.Events))
		}
		for _, event := range log.Events {
			if event.Kind == ssh.AuthOther {
				t.Fatalf("an unclassified line reached the list: %q", event.Raw)
			}
			if strings.ContainsAny(event.User, " \t\r\n") {
				t.Fatalf("account is not a bare word: %q", event.User)
			}
			if strings.ContainsAny(event.IP, " \t\r\n") {
				t.Fatalf("address is not a bare word: %q", event.IP)
			}
		}
		for _, counts := range [][]ssh.Count{log.TopIPs, log.TopUsers} {
			if len(counts) > topOffenders {
				t.Fatalf("listed %d offenders", len(counts))
			}
			for i, count := range counts {
				if count.Name == "" || count.Count <= 0 {
					t.Fatalf("empty tally entry %#v", count)
				}
				if i > 0 && counts[i-1].Count < count.Count {
					t.Fatalf("the busiest is not first: %#v", counts)
				}
			}
		}
	})
}

// FuzzParseDropIn reads back the file tui-ssh itself wrote last time. It is the
// input to the next write, so a keyword misread here is a keyword the tool then
// writes into /etc.
func FuzzParseDropIn(f *testing.F) {
	seed(f, "50-distribution.conf.txt")
	f.Add(fmt.Sprintf("%s\nPasswordAuthentication no\nPermitRootLogin no\n", dropInHeader))
	f.Fuzz(func(t *testing.T, text string) {
		for _, setting := range parseDropIn(text) {
			checkKeyword(t, setting.key)
			if strings.Contains(setting.value, "\n") {
				t.Fatalf("value spans lines: %q", setting.value)
			}
		}
	})
}
