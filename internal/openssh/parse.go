package openssh

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// splitDirective reads one configuration line into a keyword and its value.
//
// sshd's own grammar is looser than it looks: a keyword and its argument are
// separated by whitespace, or by an optional '=' with optional whitespace
// around it, and everything after a '#' is a comment. All three forms appear
// in the wild, so all three are read.
func splitDirective(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	// A trailing comment is not part of the value.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return "", "", false
	}

	// A carriage return separates like any other space: a file written on
	// Windows, or one line of it, would otherwise produce a keyword with a \r
	// inside it, which is a keyword no lookup matches and a string that walks
	// the cursor back to column 0 when the file view prints it.
	index := strings.IndexAny(line, " \t=\r")
	if index < 0 {
		// A keyword with no argument. sshd rejects it; the parser still
		// reports it so the file view can show the line that will fail.
		return line, "", true
	}
	key = line[:index]
	if key == "" {
		// A line that opens with '=' has a value and no keyword. sshd rejects
		// it, and reporting it as a directive would put a nameless row in the
		// file view and a nameless keyword in the winner table.
		return "", "", false
	}
	value = strings.TrimSpace(line[index:])
	value = strings.TrimSpace(strings.TrimPrefix(value, "="))
	return key, value, true
}

// ParseEffective reads `sshd -T` into settings.
//
// The output is one `keyword value` line per setting, with the keyword
// lower-cased and every default spelled out — which is the point of asking
// sshd instead of reading the files. A keyword that legitimately repeats
// (port, listenaddress, hostkey) gets one line each, and they are folded into
// a single space-separated value here so the table has one row per keyword.
func ParseEffective(out string) []ssh.Setting {
	order := []string{}
	values := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		key = canonicalKey(key)
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = append(values[key], value)
	}

	settings := make([]ssh.Setting, 0, len(order))
	for _, key := range order {
		settings = append(settings, ssh.Setting{
			Key:       key,
			Value:     strings.TrimSpace(strings.Join(values[key], " ")),
			Effective: true,
		})
	}
	return settings
}

// maxIncludeDepth bounds the Include recursion. sshd itself allows five levels;
// the limit here exists so a file that includes itself cannot hang the read.
const maxIncludeDepth = 8

// ReadFunc reads a configuration file. It is a parameter rather than a call to
// os.ReadFile so the include walk can be tested against fixtures, and so the
// backend can supply the escalated read a mode 0600 sshd_config needs.
type ReadFunc func(path string) (string, error)

// GlobFunc expands an Include pattern. Same reason.
type GlobFunc func(pattern string) ([]string, error)

// ParseConfigTree reads sshd_config and everything it includes, in the order
// sshd reads them.
//
// The order is the whole point. sshd takes the first value it is given for
// nearly every keyword, so which file wins is decided by where the `Include`
// sits: on a distribution that puts it at the top of sshd_config a drop-in
// wins, and on one that puts it at the bottom a keyword already set above it
// does. tui-ssh does not guess which distribution it is on — it reads the
// files and reports the winner it found.
func ParseConfigTree(read ReadFunc, glob GlobFunc, root string) []ssh.ConfigFile {
	var files []ssh.ConfigFile
	seen := map[string]bool{}
	walkConfig(read, glob, root, "", 0, 0, seen, &files)
	for i := range files {
		files[i].Order = i
	}
	return files
}

// walkConfig appends one file and, in place, everything it includes.
func walkConfig(read ReadFunc, glob GlobFunc, path, includedBy string,
	includedAt, depth int, seen map[string]bool, files *[]ssh.ConfigFile) {
	if depth > maxIncludeDepth || seen[path] {
		return
	}
	seen[path] = true

	file := ssh.ConfigFile{Path: path, IncludedBy: includedBy, IncludedAt: includedAt}
	raw, err := read(path)
	if err != nil {
		file.Unreadable = err.Error()
		*files = append(*files, file)
		return
	}
	file.Raw = raw
	file.Lines = parseLines(raw)
	*files = append(*files, file)

	// An Include splices its files in at the point it appears, so the walk
	// descends line by line rather than after the whole file.
	for _, line := range file.Lines {
		if !strings.EqualFold(line.Key, "Include") || line.Match != "" {
			continue
		}
		for _, pattern := range strings.Fields(line.Value) {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(path), pattern)
			}
			matches, globErr := glob(pattern)
			if globErr != nil {
				continue
			}
			sort.Strings(matches)
			for _, match := range matches {
				walkConfig(read, glob, match, path, line.Number, depth+1, seen, files)
			}
		}
	}
}

// parseLines turns a file's text into its parsed lines, tracking which Match
// block each one sits inside.
func parseLines(raw string) []ssh.ConfigLine {
	var lines []ssh.ConfigLine
	match := ""
	for i, text := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		line := ssh.ConfigLine{Number: i + 1, Text: text}
		if key, value, ok := splitDirective(text); ok {
			line.Key, line.Value = key, value
			if strings.EqualFold(key, "Match") {
				// A Match block runs from its own line to the next Match or to
				// end of file. The Match line itself is at file scope, so it
				// opens the block without belonging to it.
				match = value
				lines = append(lines, line)
				continue
			}
		}
		line.Match = match
		lines = append(lines, line)
	}
	return lines
}

// SourcesFor maps every keyword to the places it is written, in sshd's reading
// order. The first entry outside a Match block is the one that decides.
//
// The order is not the order of the files: an `Include` splices its files in
// at the line it appears on, so a drop-in pulled in by an Include on line 6 is
// read *before* line 17 of the file that included it. Getting that wrong would
// name the wrong winner, which is the one thing this screen is for.
func SourcesFor(files []ssh.ConfigFile) map[string][]ssh.Source {
	sources := map[string][]ssh.Source{}
	for _, entry := range Flatten(files) {
		if entry.Include {
			continue
		}
		key := strings.ToLower(entry.Key)
		sources[key] = append(sources[key], entry.Source)
	}
	return sources
}

// Directive is one line of the merged configuration, in the order sshd reads
// it. The position of a Directive in the flattened slice is what decides which
// of two settings for the same keyword sshd actually uses: the first wins.
type Directive struct {
	// Key is the keyword as it is written in the file.
	Key string
	// Include marks the `Include` line itself, which is kept in the stream so
	// the place a file would be spliced in has a position of its own.
	Include bool
	ssh.Source
}

// Flatten returns every directive of the configuration in sshd's reading
// order: each file's lines, with the files an `Include` pulls in spliced in
// where that `Include` sits.
func Flatten(files []ssh.ConfigFile) []Directive {
	return flatten(files, "", 0)
}

// flatten walks the files one `Include` site pulled in.
func flatten(files []ssh.ConfigFile, parent string, at int) []Directive {
	var out []Directive
	for _, file := range files {
		if file.IncludedBy != parent || file.IncludedAt != at {
			continue
		}
		for _, line := range file.Lines {
			if line.Key == "" || strings.EqualFold(line.Key, "Match") {
				continue
			}
			source := ssh.Source{
				File:  file.Path,
				Line:  line.Number,
				Text:  strings.TrimSpace(line.Text),
				Match: line.Match,
			}
			if strings.EqualFold(line.Key, "Include") {
				out = append(out, Directive{Key: line.Key, Include: true, Source: source})
				out = append(out, flatten(files, file.Path, line.Number)...)
				continue
			}
			out = append(out, Directive{Key: line.Key, Source: source})
		}
	}
	return out
}

// WouldWin reports whether a keyword written into the tui-ssh drop-in would be
// the value sshd uses, and names the file that would beat it when it would not.
//
// This is the question the editor has to answer before it offers to write
// anything, and it cannot be answered from a table of what each distribution
// does. sshd takes the first value it is given, so the answer depends on where
// that distribution's `Include` sits in sshd_config and on what is written
// above it — both of which are read here, from the machine in front of us.
//
// The drop-in's own position is where it would be spliced in: among the files
// the `Include` already pulls in, in the sorted order the glob returns them,
// which for `90-tui-ssh.conf` is after a distribution's `50-` fragment.
func WouldWin(files []ssh.ConfigFile, key string) (ssh.Source, bool) {
	entries := Flatten(files)
	position, ok := dropInPosition(entries, files)
	if !ok {
		return ssh.Source{}, false
	}
	for index, entry := range entries {
		if index >= position || entry.Include || entry.Match != "" {
			continue
		}
		if strings.EqualFold(entry.Key, key) {
			return entry.Source, false
		}
	}
	return ssh.Source{}, true
}

// dropInPosition is the index in the flattened stream at which the tui-ssh
// drop-in's directives sit, or would sit. It reports false when nothing
// includes the drop-in directory at all, which is the case the editor refuses
// outright rather than writing a file nothing reads.
func dropInPosition(entries []Directive, files []ssh.ConfigFile) (int, bool) {
	site, ok := IncludeSite(files)
	if !ok {
		return 0, false
	}

	// The Include's own entry, and the run of directives its files contributed
	// right after it. The run is contiguous: flatten splices it in place.
	start := -1
	for index, entry := range entries {
		if entry.Include && entry.File == site.File && entry.Line == site.Line {
			start = index
			break
		}
	}
	if start < 0 {
		return 0, false
	}

	end := start + 1
	for ; end < len(entries); end++ {
		if !includedAt(files, entries[end].File, site) {
			break
		}
		// The glob returns the fragments sorted by name, so the drop-in lands
		// before the first sibling whose name sorts after it.
		if entries[end].File == DropInPath {
			return end, true
		}
		if filepath.Base(entries[end].File) > DropInName {
			return end, true
		}
	}
	return end, true
}

// includedAt reports whether a file was pulled in by one `Include` line, or by
// an `Include` inside a file that was.
func includedAt(files []ssh.ConfigFile, path string, site ssh.Source) bool {
	for _, file := range files {
		if file.Path != path {
			continue
		}
		if file.IncludedBy == site.File && file.IncludedAt == site.Line {
			return true
		}
		if file.IncludedBy == "" {
			return false
		}
		return includedAt(files, file.IncludedBy, site)
	}
	return false
}

// SettingsFromFiles builds the settings list from the files alone. It is the
// fallback for a machine where `sshd -T` could not be run, and what it reports
// is what the files say rather than what sshd concluded — which is why the
// header says so, and why every setting it produces has Effective false.
func SettingsFromFiles(files []ssh.ConfigFile) []ssh.Setting {
	sources := SourcesFor(files)
	keys := make([]string, 0, len(sources))
	for key := range sources {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	settings := make([]ssh.Setting, 0, len(keys))
	for _, key := range keys {
		setting := ssh.Setting{Key: canonicalKey(key), Sources: sources[key]}
		if winner, ok := setting.Winner(); ok {
			_, value, _ := splitDirective(winner.Text)
			setting.Value = value
		} else {
			// Only ever set inside a Match block: there is no file-scope value.
			setting.Value = ""
		}
		settings = append(settings, setting)
	}
	return settings
}

// AttachSources folds the file evidence into settings that came from
// `sshd -T`, which knows the values but not where they were written.
func AttachSources(settings []ssh.Setting, files []ssh.ConfigFile) []ssh.Setting {
	sources := SourcesFor(files)
	for i := range settings {
		found := sources[strings.ToLower(settings[i].Key)]
		settings[i].Sources = found
		settings[i].Default = len(found) == 0
	}
	return settings
}

// IncludeSite finds the `Include` line that pulls the drop-in directory in,
// and reports whether there is one at all.
//
// It is the answer to the question every drop-in raises: will a file put there
// be read, and where in the order. A distribution that puts the Include at the
// top of sshd_config gives the drop-in the first word on every keyword; one
// that puts it at the bottom gives it the last, which for sshd means none.
// Rather than carry a table of what each distribution does, tui-ssh reads the
// line and reports what it found.
func IncludeSite(files []ssh.ConfigFile) (ssh.Source, bool) {
	for _, file := range files {
		for _, line := range file.Lines {
			if !strings.EqualFold(line.Key, "Include") || line.Match != "" {
				continue
			}
			for _, pattern := range strings.Fields(line.Value) {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(file.Path), pattern)
				}
				if filepath.Dir(pattern) != DropInDir {
					continue
				}
				return ssh.Source{
					File: file.Path,
					Line: line.Number,
					Text: strings.TrimSpace(line.Text),
				}, true
			}
		}
	}
	return ssh.Source{}, false
}

// SecurityKeys are the keywords tui-ssh has an opinion about, in the order the
// settings table shows them: who may log in, then how, then where, then what a
// session may do.
var SecurityKeys = []string{
	"PermitRootLogin",
	"PasswordAuthentication",
	"PubkeyAuthentication",
	KbdInteractiveKey,
	"PermitEmptyPasswords",
	"MaxAuthTries",
	"LoginGraceTime",
	"Port",
	"ListenAddress",
	"AllowUsers",
	"AllowGroups",
	"UsePAM",
	"X11Forwarding",
	"AllowTcpForwarding",
	"ClientAliveInterval",
	"Ciphers",
	"KexAlgorithms",
	"MACs",
}

// Order sorts the settings the way the table shows them: the security-relevant
// keywords first, in the fixed order above, then everything else
// alphabetically. It also marks which ones are security-relevant.
//
// The order is fixed rather than alphabetical because the question a reader
// arrives with is "can root log in with a password", and the answer to that
// should not be six screens down between MaxSessions and PermitTTY.
func Order(settings []ssh.Setting) []ssh.Setting {
	rank := map[string]int{}
	for i, key := range SecurityKeys {
		rank[strings.ToLower(key)] = i
	}
	// The pre-8.7 spelling ranks where the new one does, so a machine that
	// writes ChallengeResponseAuthentication still shows it at the top.
	rank[strings.ToLower(ChallengeResponseKey)] = rank[strings.ToLower(KbdInteractiveKey)]

	out := make([]ssh.Setting, len(settings))
	copy(out, settings)
	for i := range out {
		_, out[i].Security = rank[strings.ToLower(out[i].Key)]
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rank[strings.ToLower(out[i].Key)]
		rj, okj := rank[strings.ToLower(out[j].Key)]
		switch {
		case oki && okj:
			return ri < rj
		case oki != okj:
			return oki
		default:
			return strings.ToLower(out[i].Key) < strings.ToLower(out[j].Key)
		}
	})
	return out
}

// ParseLoginctlSessions reads the session ids out of
// `loginctl list-sessions --no-legend`.
//
// Only the ids are taken. The columns of that table have changed between
// systemd releases — 255 added IDLE and SINCE — so anything past the first
// field is read from `loginctl show-session` instead, which is a stable
// key=value format.
func ParseLoginctlSessions(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !sessionRe.MatchString(fields[0]) {
			continue
		}
		ids = append(ids, fields[0])
	}
	return ids
}

// ParseShowSession reads one `loginctl show-session` block into a session.
// The second return value reports whether this is an SSH login at all: logind
// tracks the console and the desktop too, and neither belongs on this screen.
func ParseShowSession(out string) (ssh.Session, bool) {
	properties := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		properties[key] = strings.TrimSpace(value)
	}

	service := properties["Service"]
	if service != "sshd" && service != "ssh" {
		return ssh.Session{}, false
	}

	session := ssh.Session{
		ID:       properties["Id"],
		User:     properties["Name"],
		RemoteIP: properties["RemoteHost"],
		TTY:      properties["TTY"],
		Since:    properties["Timestamp"],
		State:    properties["State"],
	}
	if session.ID == "" {
		// Without an id there is nothing to terminate and nothing to join the
		// socket table on, so the block is not a session this screen can use.
		return ssh.Session{}, false
	}
	if leader, err := strconv.Atoi(properties["Leader"]); err == nil {
		session.Leader = leader
	}
	return session, true
}

// ParseSSConnections reads established connections out of `ss -tnpH`.
//
// The columns are Recv-Q, Send-Q, local address:port, peer address:port and,
// when the read was privileged enough to see it, the process holding the
// socket. IPv6 addresses carry colons of their own, so the split is on the
// last colon rather than the first.
func ParseSSConnections(out string) []ssh.Session {
	var sessions []ssh.Session
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		_, localPort, ok := splitHostPort(fields[localColumn])
		if !ok {
			continue
		}
		peer, peerPort, ok := splitHostPort(fields[peerColumn])
		if !ok {
			continue
		}
		sessions = append(sessions, ssh.Session{
			RemoteIP:   peer,
			RemotePort: peerPort,
			LocalPort:  localPort,
			Leader:     pidFrom(processColumn(fields)),
		})
	}
	return sessions
}

// The columns `ss` prints for a TCP socket: the state, the two queue depths,
// the local end, the peer, and — only when the read could see it — the process
// holding the socket. `-H` drops the header row, not a column.
const (
	localColumn = 3
	peerColumn  = 4
)

// processColumn returns the field carrying the process, which is the last one
// and only present on a privileged read.
func processColumn(fields []string) string {
	last := fields[len(fields)-1]
	if !strings.HasPrefix(last, "users:(") {
		return ""
	}
	return last
}

// splitHostPort splits `address:port`, tolerating the bracketed and the bare
// IPv6 forms `ss` prints and the `*` it uses for a wildcard.
func splitHostPort(text string) (host string, port int, ok bool) {
	index := strings.LastIndexByte(text, ':')
	if index < 0 {
		return "", 0, false
	}
	host = strings.Trim(text[:index], "[]")
	port, err := strconv.Atoi(text[index+1:])
	// A number a socket cannot carry is not a port, so the field it came from
	// was not an address:port at all and the row is skipped rather than shown
	// with a port nothing is listening on.
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// pidFrom pulls the pid out of the process column, which reads
// `users:(("sshd",pid=1234,fd=4))`.
func pidFrom(text string) int {
	_, rest, found := strings.Cut(text, "pid=")
	if !found {
		return 0
	}
	end := strings.IndexAny(rest, ",)")
	if end < 0 {
		end = len(rest)
	}
	pid, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return pid
}

// MergeSessions folds what logind knows about a login into what the kernel
// knows about the socket under it.
//
// Both reads are partial on their own. logind has the account, the terminal
// and the session id that can end it, but reports the peer as a host it may
// have resolved; the socket table has the address and the port and no idea
// whose login it is. They are joined on the leader pid where both have one, and
// on the address otherwise.
func MergeSessions(logind, sockets []ssh.Session, port int) []ssh.Session {
	merged := make([]ssh.Session, 0, len(logind)+len(sockets))
	used := make([]bool, len(sockets))

	for _, session := range logind {
		for i, socket := range sockets {
			if used[i] {
				continue
			}
			if socket.Leader != 0 && socket.Leader == session.Leader ||
				socket.RemoteIP == session.RemoteIP {
				session.RemoteIP = socket.RemoteIP
				session.RemotePort = socket.RemotePort
				session.LocalPort = socket.LocalPort
				used[i] = true
				break
			}
		}
		merged = append(merged, session)
	}

	// A connection logind knows nothing about is still a connection: an sftp
	// transfer, a forced command, or a login on a machine with no logind at
	// all. It is shown with the account left blank rather than dropped.
	for i, socket := range sockets {
		if used[i] || socket.LocalPort != port {
			continue
		}
		socket.User = "(no logind session)"
		merged = append(merged, socket)
	}
	return merged
}

// ParseListeners reads `ss -tlnpH` into the sockets the server is accepting on,
// keeping only the ones held by sshd.
func ParseListeners(out string) []ssh.Listener {
	var listeners []ssh.Listener
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address, port, ok := splitHostPort(fields[localColumn])
		if !ok {
			continue
		}
		listener := ssh.Listener{
			Address: address,
			Port:    port,
			Process: processName(processColumn(fields)),
		}
		// Without the process column there is no way to tell sshd's socket
		// from anything else, so every listening socket is kept and the caller
		// filters on the configured port.
		listeners = append(listeners, listener)
	}
	return listeners
}

// processName pulls the program out of `users:(("sshd",pid=1234,fd=4))`.
func processName(text string) string {
	_, rest, found := strings.Cut(text, `(("`)
	if !found {
		return ""
	}
	name, _, found := strings.Cut(rest, `"`)
	if !found {
		return ""
	}
	return name
}

// ParseProperties reads the `key=value` output of `systemctl show`.
func ParseProperties(out string) map[string]string {
	properties := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		properties[key] = strings.TrimSpace(value)
	}
	return properties
}

// keyTypeRe is the algorithm ssh-keygen prints in parentheses at the end of a
// fingerprint line.
var keyTypeRe = regexp.MustCompile(`^\([A-Za-z0-9_-]+\)$`)

// ParseFingerprint reads one line of `ssh-keygen -lf`, which is
// `256 SHA256:… comment (ED25519)`.
func ParseFingerprint(path, out string) (ssh.HostKey, bool) {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 3 {
		return ssh.HostKey{}, false
	}
	key := ssh.HostKey{Path: path, Fingerprint: fields[1]}
	if bits, err := strconv.Atoi(fields[0]); err == nil {
		key.Bits = bits
	}
	// ssh-keygen closes the line with the algorithm in parentheses: (ED25519),
	// (RSA), (ECDSA). Anything else in that position is part of the comment,
	// which is where an unrecognised last word belongs.
	last := fields[len(fields)-1]
	if keyTypeRe.MatchString(last) {
		key.Type = strings.Trim(last, "()")
		fields = fields[:len(fields)-1]
	}
	key.Comment = strings.Join(fields[2:], " ")
	return key, key.Fingerprint != ""
}

// The shapes of the authentication lines sshd writes. They are matched as
// substrings rather than with a regular expression per message, because the
// prefix differs between the journal and /var/log/auth.log and the part that
// matters is the same in both.
const (
	markerAccepted    = "Accepted "
	markerFailed      = "Failed "
	markerInvalidUser = "Invalid user "
	markerMaxAuth     = "maximum authentication attempts exceeded"
)

// ParseAuthLog classifies the server's authentication lines and counts them.
//
// window and source are carried through rather than derived, because a reader
// has to know what was actually searched: "37 failures" means nothing without
// "in the last 24 hours, from the journal".
func ParseAuthLog(out, window, source string) ssh.AuthLog {
	log := ssh.AuthLog{Window: window, Source: source}
	failuresByIP := map[string]int{}
	failuresByUser := map[string]int{}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		event := classify(line)
		if event.Kind == ssh.AuthOther {
			continue
		}
		switch event.Kind {
		case ssh.AuthAccepted:
			log.Accepted++
		case ssh.AuthInvalidUser:
			log.InvalidUser++
			countInto(failuresByIP, event.IP)
			countInto(failuresByUser, event.User)
		case ssh.AuthFailed:
			log.Failed++
			countInto(failuresByIP, event.IP)
			countInto(failuresByUser, event.User)
		}
		log.Events = append(log.Events, event)
	}

	// Newest first: both sources print oldest first, and what a reader wants
	// on opening the screen is what just happened.
	for i, j := 0, len(log.Events)-1; i < j; i, j = i+1, j-1 {
		log.Events[i], log.Events[j] = log.Events[j], log.Events[i]
	}
	log.TopIPs = topCounts(failuresByIP)
	log.TopUsers = topCounts(failuresByUser)
	return log
}

// countInto records one failure against a name, ignoring an empty one.
func countInto(counts map[string]int, name string) {
	if name == "" {
		return
	}
	counts[name]++
}

// classify decides what one log line is, and pulls the user and the address
// out of it.
func classify(line string) ssh.AuthEvent {
	event := ssh.AuthEvent{Kind: ssh.AuthOther, Raw: line}
	switch {
	case strings.Contains(line, markerAccepted):
		event.Kind = ssh.AuthAccepted
		event.Method = wordAfter(line, markerAccepted)
	case strings.Contains(line, markerFailed):
		event.Kind = ssh.AuthFailed
		event.Method = wordAfter(line, markerFailed)
	case strings.Contains(line, markerInvalidUser):
		event.Kind = ssh.AuthInvalidUser
	case strings.Contains(line, markerMaxAuth):
		event.Kind = ssh.AuthFailed
	default:
		return event
	}

	// "Failed password for invalid user bob from 203.0.113.7 port 51234 ssh2"
	// is a failure *and* names an account that does not exist; the standalone
	// "Invalid user" line is what is counted as one, so this stays a failure.
	event.User = userFrom(line)
	event.IP = addressFrom(line)
	return event
}

// wordAfter returns the token following a marker.
func wordAfter(line, marker string) string {
	_, rest, found := strings.Cut(line, marker)
	if !found {
		return ""
	}
	// A line truncated right after the marker leaves nothing to name, so the
	// method stays blank rather than being read out of an empty field list.
	return firstField(rest)
}

// userFrom pulls the account out of an authentication line. sshd writes it
// after "for", after "for invalid user", or right after "Invalid user".
func userFrom(line string) string {
	if _, rest, found := strings.Cut(line, "for invalid user "); found {
		return firstField(rest)
	}
	if _, rest, found := strings.Cut(line, markerInvalidUser); found {
		return firstField(rest)
	}
	if _, rest, found := strings.Cut(line, " for "); found {
		return firstField(rest)
	}
	return ""
}

// addressFrom pulls the source address out of an authentication line, which
// sshd always writes after "from".
func addressFrom(line string) string {
	_, rest, found := strings.Cut(line, " from ")
	if !found {
		return ""
	}
	return firstField(rest)
}

// firstField is the first whitespace-separated token of a string.
func firstField(text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// topOffenders bounds the "top" lists. Five is what fits under the counts
// without pushing the events off the screen.
const topOffenders = 5

// topCounts turns a tally into the busiest few, most first and ties broken by
// name so the list does not shuffle between reads.
func topCounts(counts map[string]int) []ssh.Count {
	out := make([]ssh.Count, 0, len(counts))
	for name, count := range counts {
		out = append(out, ssh.Count{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > topOffenders {
		out = out[:topOffenders]
	}
	return out
}
