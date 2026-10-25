// Package hashes reads, writes and queries the file of secret hashes.
//
// Each line of a hash file is one of:
//
//	# a comment
//	12:9f86d081...0a08  # optional comment    length-tagged (preferred)
//	9f86d081...0a08                          bare hash (length unknown)
//
// The number before the colon is the length of the secret in bytes. It lets
// the matcher hash only substrings of lengths that actually occur in the file.
// Bare hashes still work, but force every substring length to be tried.
package hashes

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// EnvVar names the environment variable that lists hash files, separated like
// PATH (os.PathListSeparator).
const EnvVar = "PASSWORD_CLEANER_HASH_FILE"

// Sum is a SHA-256 digest.
type Sum [sha256.Size]byte

// Hash returns the SHA-256 digest of b.
func Hash(b []byte) Sum { return sha256.Sum256(b) }

func (s Sum) String() string { return hex.EncodeToString(s[:]) }

// Entry is one line of a hash file.
type Entry struct {
	Sum Sum
	// Length is the length of the secret in bytes, or 0 if unknown.
	Length int
	// Comment is free text kept after a "#" on the line.
	Comment string
}

// New returns the length-tagged entry for secret.
func New(secret string) Entry {
	b := []byte(secret)
	return Entry{Sum: Hash(b), Length: len(b)}
}

// String formats e as a line of a hash file.
func (e Entry) String() string {
	var sb strings.Builder
	if e.Length > 0 {
		sb.WriteString(strconv.Itoa(e.Length))
		sb.WriteByte(':')
	}
	sb.WriteString(e.Sum.String())
	if e.Comment != "" {
		sb.WriteString("  # ")
		sb.WriteString(e.Comment)
	}
	return sb.String()
}

// ParseLine parses one line of a hash file. ok is false, with a nil error, for
// blank lines and comments. Errors never include the text of the line, since
// a mistyped line may well be a secret.
func ParseLine(line string) (e Entry, ok bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return Entry{}, false, nil
	}
	body, comment, _ := strings.Cut(line, "#")
	body = strings.TrimSpace(body)
	e.Comment = strings.TrimSpace(comment)

	if strings.ContainsAny(body, " \t") {
		return Entry{}, false, errors.New("unexpected text after the hash")
	}
	hexPart := body
	if lenPart, rest, tagged := strings.Cut(body, ":"); tagged {
		n, convErr := strconv.Atoi(lenPart)
		if convErr != nil || n < 1 {
			return Entry{}, false, errors.New("the length before ':' must be a positive number")
		}
		e.Length = n
		hexPart = rest
	}
	if len(hexPart) != 2*len(e.Sum) {
		return Entry{}, false, fmt.Errorf("expected %d hex characters", 2*len(e.Sum))
	}
	if _, decErr := hex.Decode(e.Sum[:], []byte(hexPart)); decErr != nil {
		return Entry{}, false, errors.New("not valid hex")
	}
	return e, true, nil
}

// Set is a collection of hashes, indexed for fast lookup.
type Set struct {
	tagged  map[int]map[Sum]struct{}
	legacy  map[Sum]struct{}
	lengths []int // distinct tagged lengths, ascending
}

// NewSet returns an empty set.
func NewSet() *Set {
	return &Set{tagged: map[int]map[Sum]struct{}{}, legacy: map[Sum]struct{}{}}
}

// Add inserts e and reports whether it was new.
func (s *Set) Add(e Entry) bool {
	if e.Length <= 0 {
		if _, ok := s.legacy[e.Sum]; ok {
			return false
		}
		s.legacy[e.Sum] = struct{}{}
		return true
	}
	m, ok := s.tagged[e.Length]
	if !ok {
		m = map[Sum]struct{}{}
		s.tagged[e.Length] = m
		i, _ := slices.BinarySearch(s.lengths, e.Length)
		s.lengths = slices.Insert(s.lengths, i, e.Length)
	}
	if _, dup := m[e.Sum]; dup {
		return false
	}
	m[e.Sum] = struct{}{}
	return true
}

// Len returns the number of hashes in the set.
func (s *Set) Len() int {
	n := len(s.legacy)
	for _, m := range s.tagged {
		n += len(m)
	}
	return n
}

// Lengths returns the distinct lengths of the tagged hashes, ascending. The
// caller must not modify it.
func (s *Set) Lengths() []int { return s.lengths }

// HasLength reports whether any tagged hash has length n.
func (s *Set) HasLength(n int) bool {
	_, ok := s.tagged[n]
	return ok
}

// HasLegacy reports whether the set holds any bare (untagged) hashes.
func (s *Set) HasLegacy() bool { return len(s.legacy) > 0 }

// Tagged reports whether a secret of the given length has this hash.
func (s *Set) Tagged(length int, sum Sum) bool {
	_, ok := s.tagged[length][sum]
	return ok
}

// Legacy reports whether sum is a bare hash in the set.
func (s *Set) Legacy(sum Sum) bool {
	_, ok := s.legacy[sum]
	return ok
}

// Contains reports whether sum is in the set, tagged or not.
func (s *Set) Contains(sum Sum) bool {
	if s.Legacy(sum) {
		return true
	}
	for _, m := range s.tagged {
		if _, ok := m[sum]; ok {
			return true
		}
	}
	return false
}

// LoadFile adds every entry in the file at path to s and returns how many it
// read. Malformed lines are skipped and reported to warn (which may be nil)
// as "path:line: reason".
func (s *Set) LoadFile(path string, warn func(msg string)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	n, lineNo := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNo++
		e, ok, perr := ParseLine(sc.Text())
		if perr != nil {
			if warn != nil {
				warn(fmt.Sprintf("%s:%d: %v", path, lineNo, perr))
			}
			continue
		}
		if ok {
			s.Add(e)
			n++
		}
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("reading %s: %w", path, err)
	}
	return n, nil
}

// DefaultPath returns where the hash file lives when nothing else is
// configured: $XDG_CONFIG_HOME/password-cleaner/hashes.txt if that variable
// is set, otherwise under the user's config directory (on macOS, ~/.config if
// it exists, falling back to ~/Library/Application Support).
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(dir) {
		var err error
		dir, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("unable to determine the config directory: %w", err)
		}
		if runtime.GOOS == "darwin" {
			if home, err := os.UserHomeDir(); err == nil {
				dot := filepath.Join(home, ".config")
				if info, err := os.Stat(dot); err == nil && info.IsDir() {
					dir = dot
				}
			}
		}
	}
	return filepath.Join(dir, "password-cleaner", "hashes.txt"), nil
}

// Resolve picks the hash files to use: the explicit list if there is one, then
// $PASSWORD_CLEANER_HASH_FILE, then the default path. isDefault reports
// whether the default was used.
func Resolve(explicit []string) (paths []string, isDefault bool, err error) {
	if len(explicit) > 0 {
		return explicit, false, nil
	}
	if env := os.Getenv(EnvVar); env != "" {
		var out []string
		for _, p := range filepath.SplitList(env) {
			if p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out, false, nil
		}
	}
	p, err := DefaultPath()
	if err != nil {
		return nil, false, err
	}
	return []string{p}, true, nil
}

// AppendResult says what Append did with the entries it was given.
type AppendResult struct {
	Added    int // written as new lines
	Upgraded int // bare lines rewritten to include the secret's length
	Skipped  int // already present, so left alone
}

// Append adds entries to the hash file at path, creating it (mode 0600) and
// its directory (mode 0700) if needed.
//
// An entry whose hash is already in the file is skipped, with one exception:
// if the existing line is a bare hash and the entry knows its length, that
// line is rewritten in place to the length-tagged form. The line keeps its
// own comment; if it had none it takes the entry's. With replaceComment the
// entry's comment replaces the line's whenever the entry has one. Every other
// line is left exactly as it was.
func Append(path string, entries []Entry, replaceComment bool) (res AppendResult, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, err
	}
	var content string
	switch data, err := os.ReadFile(path); {
	case err == nil:
		content = string(data)
	case !errors.Is(err, fs.ErrNotExist):
		return res, err
	}

	lines := strings.Split(content, "\n")
	seen := NewSet()
	bare := map[Sum][]int{} // line numbers of bare hashes
	for i, raw := range lines {
		e, ok, perr := ParseLine(strings.TrimSuffix(raw, "\r"))
		if perr != nil || !ok {
			continue
		}
		seen.Add(e)
		if e.Length == 0 {
			bare[e.Sum] = append(bare[e.Sum], i)
		}
	}

	var added strings.Builder
	for _, e := range entries {
		switch idx, isBare := bare[e.Sum]; {
		case isBare && e.Length > 0:
			for _, i := range idx {
				raw := lines[i]
				cr := ""
				if strings.HasSuffix(raw, "\r") {
					raw, cr = strings.TrimSuffix(raw, "\r"), "\r"
				}
				old, _, _ := ParseLine(raw)
				up := Entry{Sum: e.Sum, Length: e.Length, Comment: old.Comment}
				if e.Comment != "" && (replaceComment || old.Comment == "") {
					up.Comment = e.Comment
				}
				lines[i] = up.String() + cr
			}
			delete(bare, e.Sum)
			seen.Add(Entry{Sum: e.Sum, Length: e.Length})
			res.Upgraded++
		case seen.Contains(e.Sum):
			res.Skipped++
		default:
			seen.Add(e)
			added.WriteString(e.String())
			added.WriteByte('\n')
			res.Added++
		}
	}
	if res.Added == 0 && res.Upgraded == 0 {
		return res, nil
	}

	if res.Upgraded > 0 {
		// Lines changed, so replace the whole file, atomically.
		out := strings.Join(lines, "\n")
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		return res, replaceFile(path, out+added.String())
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return res, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	out := added.String()
	if content != "" && !strings.HasSuffix(content, "\n") {
		out = "\n" + out
	}
	_, err = f.WriteString(out)
	return res, err
}

// replaceFile atomically replaces the file at path with content, keeping its
// permissions. If path is a symlink the file it points to is replaced.
func replaceFile(path, content string) (err error) {
	if target, rerr := filepath.EvalSymlinks(path); rerr == nil {
		path = target
	}
	mode := os.FileMode(0o600)
	if info, serr := os.Stat(path); serr == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hashes-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
