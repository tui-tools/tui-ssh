package openssh

import (
	"fmt"
	"strings"
	"testing"
)

// samplePasswd is the shape /etc/passwd has on a real machine: a pile of system
// accounts nobody logs into, and two or three that somebody does.
//
//nolint:gosec // G101: /etc/passwd carries an `x` where the password used to be; there is no credential in this fixture
const samplePasswd = `root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/usr/sbin/nologin
nobody:x:65534:65534:Nobody:/:/sbin/nologin
deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash
ana:x:1001:2000:Ana:/home/ana:/bin/zsh
broken:x:1002:1002:Broken:relative/home:/bin/bash
`

// anaHome is the second sample account's home; deployHome is declared with the
// key fixtures the command builders use.
const anaHome = "/home/ana"

const sampleGroup = `root:x:0:
deploy:x:1000:
developers:x:2000:ana
`

func TestParsePasswd(t *testing.T) {
	users := ParsePasswd(samplePasswd, ParseGroups(sampleGroup))

	var names []string
	for _, user := range users {
		names = append(names, user.Name)
	}
	// root first, then the ordinary accounts alphabetically. The system
	// accounts are gone: an account with a nologin shell is not one somebody
	// logs into, and listing it would bury the two that matter.
	want := []string{"root", "ana", "deploy"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("accounts = %v, want %v", names, want)
	}

	// The primary group is resolved through /etc/group, because that is the
	// name `install -g` takes.
	byName := map[string]string{}
	for _, user := range users {
		byName[user.Name] = user.Group
	}
	if byName["ana"] != "developers" {
		t.Errorf("ana's group = %q, want developers", byName["ana"])
	}
	if byName["deploy"] != "deploy" {
		t.Errorf("deploy's group = %q", byName["deploy"])
	}

	// An account whose home is not a path this tool would write to is not
	// offered at all: the picker must only list accounts whose plan can be
	// built.
	for _, user := range users {
		if user.Name == "broken" {
			t.Errorf("an account with a relative home was offered")
		}
		if err := CheckUser(user); err != nil {
			t.Errorf("%s was offered and then refused: %v", user.Name, err)
		}
	}

	// The keys file of each is the default location, derived rather than
	// guessed.
	for _, user := range users {
		if user.KeysPath != user.Home+"/.ssh/authorized_keys" {
			t.Errorf("%s: keys path = %q", user.Name, user.KeysPath)
		}
	}
}

func TestParsePasswdIgnoresRubbish(t *testing.T) {
	users := ParsePasswd("\n#comment\nnot:enough:fields\nx:y:z:1:2:3:4\n", nil)
	if len(users) != 0 {
		t.Errorf("parsed %d accounts out of nothing usable: %+v", len(users), users)
	}
}

func TestLoadAuthorizedKeys(t *testing.T) {
	users := ParsePasswd(samplePasswd, ParseGroups(sampleGroup))
	files := map[string]string{
		AuthorizedKeysPathFor(deployHome): keyFixtures[0].line + "\n" +
			keyFixtures[2].line + "\n",
	}
	read := func(path string) (string, error) {
		if raw, ok := files[path]; ok {
			return raw, nil
		}
		if path == AuthorizedKeysPathFor(anaHome) {
			// Another account's ~/.ssh is mode 700, and this is what an
			// unprivileged read of it looks like when the escalation is not
			// available either.
			return "", fmt.Errorf("open %s: permission denied", path)
		}
		return "", fmt.Errorf("open %s: no such file or directory", path)
	}

	loaded := LoadAuthorizedKeys(users, read)
	byName := map[string]int{}
	for _, user := range loaded {
		byName[user.Name] = len(user.Keys)
		switch user.Name {
		case "deploy":
			if user.Unreadable != "" {
				t.Errorf("deploy's file read fine but was reported unreadable")
			}
		case "ana":
			// "no keys" and "we were not allowed to look" are answers a reader
			// must not confuse, so the second one is carried through.
			if user.Unreadable == "" {
				t.Errorf("a file that could not be read was reported as empty")
			}
		case "root":
			if user.Unreadable != "" {
				t.Errorf("an account with no key file is not an error: %q",
					user.Unreadable)
			}
		}
	}
	if byName["deploy"] != 2 {
		t.Errorf("deploy has %d keys, want 2", byName["deploy"])
	}
	if byName["ana"] != 0 || byName["root"] != 0 {
		t.Errorf("keys = %+v", byName)
	}
}
