package openssh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// The two files an authorized key change touches, and the modes they get.
//
// sshd refuses a key it does not trust the permissions of: with StrictModes on,
// which is the default, a group-writable ~/.ssh or authorized_keys is ignored
// and the user is left staring at a key that is plainly there and plainly not
// working. So the modes are part of the plan rather than left to the umask.
const (
	// SSHDirName is the per-account directory the key file lives in.
	SSHDirName = ".ssh"
	// AuthorizedKeysName is the file sshd reads a user's keys from. It is the
	// default of `AuthorizedKeysFile`; an account whose sshd_config points
	// somewhere else is not one this tool writes.
	AuthorizedKeysName = "authorized_keys"
	// SSHDirMode is the mode ~/.ssh gets: nobody but the account.
	SSHDirMode = "700"
	// AuthorizedKeysMode is the mode the key file gets.
	AuthorizedKeysMode = "600"
)

// maxAuthorizedKeysBytes bounds the file that is read and rewritten. A real
// authorized_keys is a few kilobytes; anything past this is not a file this
// tool should be staging a copy of in memory.
const maxAuthorizedKeysBytes = 1 << 20

// userNameRe accepts a local account name, which ends up in an `install -o`
// argument. It is the useradd(8) shape: lower-case start, then the small set
// of characters a portable account name may carry.
var userNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)

// homePathRe accepts a home directory: absolute, and made only of characters
// that cannot turn one argv word into two. A `..` is refused separately,
// because a path that walks upwards would move where the key file lands.
var homePathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,255}$`)

// keyTypeNames maps the wire name of a public key to the name ssh-keygen
// prints, which is the name the screen shows.
var keyTypeNames = map[string]string{
	"ssh-ed25519":                        "ED25519",
	"sk-ssh-ed25519@openssh.com":         "ED25519-SK",
	"ssh-rsa":                            "RSA",
	"rsa-sha2-256":                       "RSA",
	"rsa-sha2-512":                       "RSA",
	"ssh-dss":                            "DSA",
	"ecdsa-sha2-nistp256":                "ECDSA",
	"ecdsa-sha2-nistp384":                "ECDSA",
	"ecdsa-sha2-nistp521":                "ECDSA",
	"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
}

// curveBits is the key size of each ECDSA curve, which is in the curve's own
// name rather than anywhere in the blob.
var curveBits = map[string]int{
	"nistp256": 256,
	"nistp384": 384,
	"nistp521": 521,
}

// SSHDirFor is the ~/.ssh of an account.
func SSHDirFor(home string) string {
	return strings.TrimSuffix(home, "/") + "/" + SSHDirName
}

// AuthorizedKeysPathFor is the authorized_keys of an account.
func AuthorizedKeysPathFor(home string) string {
	return SSHDirFor(home) + "/" + AuthorizedKeysName
}

// CheckUser validates the account a key change is about. Both fields end up in
// an argv that runs as root, so neither is taken on trust — not even from
// /etc/passwd, which is a file this tool reads rather than a source it owns.
func CheckUser(user ssh.User) error {
	if !userNameRe.MatchString(user.Name) {
		return fmt.Errorf("openssh: %q is not a local account name", user.Name)
	}
	if user.Group != "" && !userNameRe.MatchString(user.Group) {
		return fmt.Errorf("openssh: %q is not a group name", user.Group)
	}
	if !homePathRe.MatchString(user.Home) ||
		strings.Contains(user.Home, "..") || user.Home == "/" {
		return fmt.Errorf("openssh: %s has no home directory this tool will write to",
			user.Name)
	}
	return nil
}

// groupOf is the group a new file under the account's home belongs to. An
// account whose primary group could not be read falls back to its own name,
// which is what every distribution's useradd creates.
func groupOf(user ssh.User) string {
	if user.Group != "" {
		return user.Group
	}
	return user.Name
}

// ParseAuthorizedKey reads one line of an authorized_keys file.
//
// The grammar is `[options] type base64 [comment]`, and the options are what
// makes it awkward: they are optional, they may contain quoted spaces, and
// nothing marks where they end. So the line is scanned for the first field
// that decodes as a public key blob of its own name — which is the same thing
// that makes the key a key, and needs no table of option spellings.
func ParseAuthorizedKey(line string) (ssh.AuthorizedKey, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ssh.AuthorizedKey{}, false
	}
	// A control character inside the line is not something a key file should
	// carry, and this parser's output is copied verbatim into the file that
	// replaces it — so a stray carriage return would be written back, and would
	// walk the cursor to column 0 in the table on the way. A line like that is
	// left alone rather than understood.
	if strings.ContainsFunc(trimmed, isControl) {
		return ssh.AuthorizedKey{}, false
	}
	fields := strings.Fields(trimmed)
	for i := 0; i+1 < len(fields); i++ {
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil || !blobNames(blob, fields[i]) {
			continue
		}
		key := ssh.AuthorizedKey{
			Options:     strings.Join(fields[:i], " "),
			Type:        keyTypeName(fields[i]),
			Bits:        keyBits(fields[i], blob),
			Fingerprint: Fingerprint(blob),
			Comment:     strings.Join(fields[i+2:], " "),
			Raw:         trimmed,
		}
		return key, true
	}
	return ssh.AuthorizedKey{}, false
}

// isControl reports a character no configuration line has a use for. Tab is
// not one of them: it separates a keyword from its argument as happily as a
// space does.
func isControl(r rune) bool {
	return r != '\t' && (r < 0x20 || r == 0x7f)
}

// blobNames reports that a decoded blob is a public key of the named type.
//
// Every SSH public key opens with its own type as the first wire string and
// carries at least one parameter after it, so this is both the parse and the
// check that the base64 was a key at all: a truncated blob that is nothing but
// its own name — which is what a half-copied paste looks like — fails here
// rather than being installed as a key nothing can authenticate with.
func blobNames(blob []byte, want string) bool {
	name, rest, ok := readWireString(blob)
	if !ok || string(name) != want {
		return false
	}
	_, _, hasBody := readWireString(rest)
	return hasBody
}

// keyTypeName is the name ssh-keygen prints for a wire type.
func keyTypeName(wire string) string {
	if name, ok := keyTypeNames[wire]; ok {
		return name
	}
	return strings.ToUpper(wire)
}

// keyBits derives the key size from the blob, the way ssh-keygen reports it.
// A type this function does not know returns 0, which the screen shows as an
// em dash rather than as a wrong number.
func keyBits(wire string, blob []byte) int {
	switch {
	case strings.Contains(wire, "ed25519"):
		return 256
	case strings.HasPrefix(wire, "ecdsa-sha2-"), strings.Contains(wire, "ecdsa-sha2-nistp"):
		return curveBits[strings.TrimPrefix(
			strings.TrimSuffix(wire, "@openssh.com"), "ecdsa-sha2-")]
	case wire == "ssh-rsa" || strings.HasPrefix(wire, "rsa-sha2-"):
		// ssh-rsa is name, e, n: the modulus is the third wire string, and its
		// bit length is the size everybody means by "a 3072-bit key".
		return mpintBits(blob, 2)
	case wire == "ssh-dss":
		// ssh-dss is name, p, q, g, y, and it is p that gives the size.
		return mpintBits(blob, 1)
	default:
		return 0
	}
}

// mpintBits reads the nth wire string of a blob as a big-endian integer and
// returns its bit length.
func mpintBits(blob []byte, index int) int {
	rest := blob
	for i := 0; i <= index; i++ {
		value, remainder, ok := readWireString(rest)
		if !ok {
			return 0
		}
		if i == index {
			return new(big.Int).SetBytes(value).BitLen()
		}
		rest = remainder
	}
	return 0
}

// readWireString reads one length-prefixed field of the SSH wire format.
func readWireString(blob []byte) (value, rest []byte, ok bool) {
	if len(blob) < 4 {
		return nil, nil, false
	}
	// The length is compared in int64, which every uint32 fits into without
	// losing anything: a blob whose header claims more than the blob carries is
	// a truncated paste, and it stops here.
	length := binary.BigEndian.Uint32(blob[:4])
	if int64(length) > int64(len(blob)-4) {
		return nil, nil, false
	}
	return blob[4 : 4+length], blob[4+length:], true
}

// Fingerprint is the SHA256 fingerprint of a public key blob, in the form
// ssh-keygen prints: the base64 of the digest, unpadded, behind `SHA256:`.
//
// It is computed here rather than shelled out for, because the alternative is
// one `ssh-keygen -lf` per key per read, and because a fingerprint is what a
// key is identified by when one is removed — a value that has to be derived
// from the line itself rather than from the position of a line in a file that
// may have changed since it was listed.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ParseAuthorizedKeys reads a whole authorized_keys file.
func ParseAuthorizedKeys(raw string) []ssh.AuthorizedKey {
	var keys []ssh.AuthorizedKey
	for i, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		key, ok := ParseAuthorizedKey(line)
		if !ok {
			continue
		}
		key.Line = i + 1
		keys = append(keys, key)
	}
	return keys
}

// CheckPublicKey validates a pasted public key before anything is staged: that
// it is one key, that it parses, and that it carries nothing that would make
// the file say more than the user thinks it says.
//
// It is deliberately stricter than authorized_keys allows. A pasted line with
// options in front of it is refused rather than installed, because a form that
// silently accepted `command="…"` from a paste would be a way to write an
// arbitrary forced command into somebody's account without ever showing it as
// what it is.
func CheckPublicKey(pasted string) (ssh.AuthorizedKey, error) {
	trimmed := strings.TrimSpace(pasted)
	if trimmed == "" {
		return ssh.AuthorizedKey{}, fmt.Errorf("openssh: paste a public key first")
	}
	if strings.ContainsAny(trimmed, "\n\r") {
		return ssh.AuthorizedKey{}, fmt.Errorf(
			"openssh: paste one key on one line; this is %d lines",
			len(strings.Split(trimmed, "\n")))
	}
	if strings.Contains(trimmed, "PRIVATE KEY") {
		return ssh.AuthorizedKey{}, fmt.Errorf(
			"openssh: that is a PRIVATE key — authorized_keys takes the .pub half")
	}
	key, ok := ParseAuthorizedKey(trimmed)
	if !ok {
		return ssh.AuthorizedKey{}, fmt.Errorf(
			"openssh: that is not a public key — a line starts with its type, " +
				"as in `ssh-ed25519 AAAAC3… you@laptop`")
	}
	if key.Options != "" {
		return ssh.AuthorizedKey{}, fmt.Errorf(
			"openssh: this key carries the options %q; tui-ssh installs a plain "+
				"key, so remove them or edit %s by hand",
			key.Options, AuthorizedKeysName)
	}
	return key, nil
}

// RenderAuthorizedKeysWith returns the new text of an authorized_keys file with
// one key appended.
//
// The file is appended to rather than regenerated, which is the opposite of
// what the drop-in editor does and for the opposite reason: this file is not
// one tui-ssh owns. Somebody's comments, their `from=` restrictions and their
// ordering are theirs, and a change that added a key by rewriting the file
// would be a change that quietly dropped whatever it did not understand.
func RenderAuthorizedKeysWith(existing string, key ssh.AuthorizedKey) (string, error) {
	for _, present := range ParseAuthorizedKeys(existing) {
		if present.Fingerprint == key.Fingerprint {
			return "", fmt.Errorf("openssh: this key is already there, on line %d",
				present.Line)
		}
	}
	out := existing
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + key.Raw + "\n", nil
}

// RenderAuthorizedKeysWithout returns the new text of an authorized_keys file
// with the key of this fingerprint taken out, and everything else — comments,
// blank lines, the other keys, byte for byte — left as it was.
func RenderAuthorizedKeysWithout(existing, fingerprint string) (string, error) {
	if !fingerprintRe.MatchString(fingerprint) {
		return "", fmt.Errorf("openssh: %q is not a SHA256 fingerprint", fingerprint)
	}
	lines := strings.Split(strings.TrimSuffix(existing, "\n"), "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if key, ok := ParseAuthorizedKey(line); ok && key.Fingerprint == fingerprint {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return "", fmt.Errorf(
			"openssh: no key with fingerprint %s is in this file any more; "+
				"press R to re-read the server", fingerprint)
	}
	out := strings.Join(kept, "\n")
	if strings.TrimSpace(out) == "" {
		// Every key is gone. The file stays, empty: removing it would be a
		// second decision the user did not make, and sshd is happy with an
		// empty one.
		return "", nil
	}
	return out + "\n", nil
}

// fingerprintRe accepts the fingerprint form ssh-keygen prints, which is what
// a key is selected by when one is removed.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// BuildCreateSSHDir creates ~/.ssh owned by the account, mode 700.
//
// `install -d` is used rather than mkdir because it sets the mode and the
// owner in the same call: there is no window in which the directory exists
// with the wrong permissions, which is the window StrictModes would refuse the
// key in.
func BuildCreateSSHDir(user ssh.User) (ssh.Command, error) {
	if err := CheckUser(user); err != nil {
		return ssh.Command{}, err
	}
	dir := SSHDirFor(user.Home)
	return ssh.Command{
		Argv: []string{"install", "-d", "-m", SSHDirMode,
			"-o", user.Name, "-g", groupOf(user), dir},
		Description: "Create " + dir + " owned by " + user.Name +
			", mode " + SSHDirMode + " (it may already exist)",
		Destructive: true,
	}, nil
}

// BuildInstallAuthorizedKeys copies a staged authorized_keys into the account's
// home, owned by the account and mode 600.
func BuildInstallAuthorizedKeys(tempPath string, user ssh.User) (ssh.Command, error) {
	if !stagedRe.MatchString(tempPath) {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not a staging path", tempPath)
	}
	if err := CheckUser(user); err != nil {
		return ssh.Command{}, err
	}
	destination := AuthorizedKeysPathFor(user.Home)
	return ssh.Command{
		Argv: []string{"install", "-m", AuthorizedKeysMode,
			"-o", user.Name, "-g", groupOf(user), tempPath, destination},
		Description: "Install " + tempPath + " as " + destination +
			", owned by " + user.Name,
		Destructive: true,
	}, nil
}

// BuildFingerprintKey asks ssh-keygen what it makes of a staged key file.
//
// It is a read, and it runs before the user is asked anything, for the same
// reason `sshd -t -f` does on the configuration side: the program that will
// have to accept this key is the one that says whether it is a key, and its
// answer — the fingerprint — is what the dialog then shows.
func BuildFingerprintKey(tempPath string) (ssh.Command, error) {
	if !stagedRe.MatchString(tempPath) {
		return ssh.Command{}, fmt.Errorf("openssh: %q is not a staging path", tempPath)
	}
	return ssh.Command{
		Argv:        []string{"ssh-keygen", "-l", "-f", tempPath},
		Description: "Ask ssh-keygen to read " + tempPath,
	}, nil
}
