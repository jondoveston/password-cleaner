package hashes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// "password" hashes to this.
const passwordSum = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

func TestHash(t *testing.T) {
	if got := Hash([]byte("password")).String(); got != passwordSum {
		t.Errorf("got %s", got)
	}
}

func TestEntryRoundTrip(t *testing.T) {
	e := New("password")
	e.Label = "my bank"
	line := e.String()
	if want := "8:" + passwordSum + "  # my bank"; line != want {
		t.Fatalf("got %q, want %q", line, want)
	}
	got, ok, err := ParseLine(line)
	if err != nil || !ok || got != e {
		t.Errorf("round trip: got %+v ok=%v err=%v", got, ok, err)
	}
}

func TestParseLine(t *testing.T) {
	upper := strings.ToUpper(passwordSum)
	tests := []struct {
		name    string
		line    string
		ok      bool
		length  int
		label   string
		wantErr string
	}{
		{name: "blank", line: "   "},
		{name: "comment", line: "# nothing here"},
		{name: "bare", line: passwordSum, ok: true},
		{name: "bare with spaces around", line: "  " + passwordSum + "\t", ok: true},
		{name: "upper case", line: upper, ok: true},
		{name: "tagged", line: "8:" + passwordSum, ok: true, length: 8},
		{name: "label", line: "8:" + passwordSum + " # a # b", ok: true, length: 8, label: "a # b"},
		{name: "bare label", line: passwordSum + "# x", ok: true, label: "x"},
		{name: "short", line: "abc123", wantErr: "expected 64 hex"},
		{name: "not hex", line: strings.Repeat("z", 64), wantErr: "not valid hex"},
		{name: "zero length", line: "0:" + passwordSum, wantErr: "positive number"},
		{name: "negative length", line: "-3:" + passwordSum, wantErr: "positive number"},
		{name: "length not a number", line: "x:" + passwordSum, wantErr: "positive number"},
		{name: "trailing text", line: passwordSum + " extra", wantErr: "unexpected text"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, ok, err := ParseLine(tc.line)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got err %v, want %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), tc.line) && len(tc.line) > 3 {
					t.Errorf("error repeats the line: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.ok {
				t.Fatalf("ok = %v", ok)
			}
			if ok && (e.Length != tc.length || e.Label != tc.label || e.Sum.String() != passwordSum) {
				t.Errorf("got %+v", e)
			}
		})
	}
}

func TestSet(t *testing.T) {
	s := NewSet()
	pw := Hash([]byte("password"))
	other := Hash([]byte("hunter22"))

	if !s.Add(Entry{Sum: pw, Length: 8}) || s.Add(Entry{Sum: pw, Length: 8}) {
		t.Error("Add should report only the first insert as new")
	}
	s.Add(Entry{Sum: Hash([]byte("abcd")), Length: 4})
	s.Add(Entry{Sum: Hash([]byte("a longer secret")), Length: 15})
	if !slices.Equal(s.Lengths(), []int{4, 8, 15}) {
		t.Errorf("Lengths = %v", s.Lengths())
	}
	if !s.Tagged(8, pw) || s.Tagged(7, pw) || s.Tagged(8, other) {
		t.Error("Tagged lookup wrong")
	}
	if s.HasLegacy() || s.Legacy(pw) {
		t.Error("no legacy entries yet")
	}
	if !s.Add(Entry{Sum: other}) || s.Add(Entry{Sum: other}) {
		t.Error("legacy Add wrong")
	}
	if !s.HasLegacy() || !s.Legacy(other) || !s.Contains(other) || !s.Contains(pw) {
		t.Error("legacy lookup wrong")
	}
	if s.Contains(Hash([]byte("nope"))) {
		t.Error("Contains false positive")
	}
	if s.Len() != 4 || !s.HasLength(4) || s.HasLength(5) {
		t.Errorf("Len=%d", s.Len())
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	content := "# header\n\n8:" + passwordSum + "\nbad line here\n" + passwordSum + "\n0:" + passwordSum + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	s := NewSet()
	n, err := s.LoadFile(path, func(m string) { warnings = append(warnings, m) })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || s.Len() != 2 {
		t.Errorf("read %d, set has %d", n, s.Len())
	}
	if len(warnings) != 2 ||
		!strings.HasPrefix(warnings[0], path+":4: ") ||
		!strings.HasPrefix(warnings[1], path+":6: ") {
		t.Errorf("warnings = %q", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w, "bad line here") {
			t.Errorf("warning repeats the line: %q", w)
		}
	}

	if _, err := NewSet().LoadFile(filepath.Join(t.TempDir(), "missing"), nil); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

func TestAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "hashes.txt")

	res, err := Append(path, []Entry{New("password"), New("password"), New("hunter22")})
	if err != nil || res != (AppendResult{Added: 2, Skipped: 1}) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	res, err = Append(path, []Entry{New("hunter22"), New("another one")})
	if err != nil || res != (AppendResult{Added: 1, Skipped: 1}) {
		t.Fatalf("second append: res=%+v err=%v", res, err)
	}
	res, err = Append(path, []Entry{New("password")})
	if err != nil || res != (AppendResult{Skipped: 1}) {
		t.Fatalf("all duplicates: res=%+v err=%v", res, err)
	}

	s := NewSet()
	if _, err := s.LoadFile(path, nil); err != nil || s.Len() != 3 {
		t.Fatalf("len=%d err=%v", s.Len(), err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v", info.Mode().Perm())
		}
		dir, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dir.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v", dir.Mode().Perm())
		}
	}
}

func TestAppendAddsMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	if err := os.WriteFile(path, []byte("# no trailing newline"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, []Entry{New("password")}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if want := "# no trailing newline\n8:" + passwordSum + "\n"; string(data) != want {
		t.Errorf("got %q", data)
	}
}

func hunterSum() string { return New("hunter22").Sum.String() }

func TestAppendUpgradesBareHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	before := "# my secrets\n\n" + passwordSum + "  # bank\n" + hunterSum() + "\nnot a hash\n" +
		"8:" + hunterSum() + "\n"
	// The last line is a tagged duplicate of the one above it; it must survive.
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}

	res, err := Append(path, []Entry{New("password"), New("a new secret")})
	if err != nil || res != (AppendResult{Added: 1, Upgraded: 1}) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	data, _ := os.ReadFile(path)
	want := "# my secrets\n\n8:" + passwordSum + "  # bank\n" + hunterSum() + "\nnot a hash\n" +
		"8:" + hunterSum() + "\n" +
		"12:" + New("a new secret").Sum.String() + "\n"
	if string(data) != want {
		t.Errorf("got:\n%s\nwant:\n%s", data, want)
	}

	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o640 {
			t.Errorf("mode changed to %v", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}

	// A second run finds it already upgraded.
	res, err = Append(path, []Entry{New("password")})
	if err != nil || res != (AppendResult{Skipped: 1}) {
		t.Errorf("second run: res=%+v err=%v", res, err)
	}
}

func TestAppendUpgradeLabel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	write := func() {
		if err := os.WriteFile(path, []byte(passwordSum+"  # old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write()
	if _, err := Append(path, []Entry{New("password")}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "8:"+passwordSum+"  # old\n" {
		t.Errorf("label should be kept: %q", data)
	}

	write()
	e := New("password")
	e.Label = "new"
	if _, err := Append(path, []Entry{e}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "8:"+passwordSum+"  # new\n" {
		t.Errorf("label should be replaced: %q", data)
	}
}

func TestAppendUpgradeKeepsCRLFAndMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	if err := os.WriteFile(path, []byte("# c\r\n"+passwordSum), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, []Entry{New("password"), New("hunter22")}); err != nil {
		t.Fatal(err)
	}
	want := "# c\r\n8:" + passwordSum + "\n8:" + hunterSum() + "\n"
	if data, _ := os.ReadFile(path); string(data) != want {
		t.Errorf("got %q, want %q", data, want)
	}
}

func TestAppendUpgradeThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte(passwordSum+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(link, []Entry{New("password")}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if data, _ := os.ReadFile(target); string(data) != "8:"+passwordSum+"\n" {
		t.Errorf("target not upgraded: %q", data)
	}
}

func TestAppendBareEntryDoesNotUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	if err := os.WriteFile(path, []byte(passwordSum+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An entry with no length has nothing to upgrade to.
	e := New("password")
	e.Length = 0
	res, err := Append(path, []Entry{e})
	if err != nil || res != (AppendResult{Skipped: 1}) {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestDefaultPath(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(xdg, "password-cleaner", "hashes.txt"); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestResolve(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv(EnvVar, "")

	paths, isDefault, err := Resolve(nil)
	if err != nil || !isDefault || len(paths) != 1 || !strings.HasPrefix(paths[0], xdg) {
		t.Errorf("default: %v %v %v", paths, isDefault, err)
	}

	sep := string(os.PathListSeparator)
	t.Setenv(EnvVar, "/a"+sep+sep+"/b")
	paths, isDefault, _ = Resolve(nil)
	if isDefault || !slices.Equal(paths, []string{"/a", "/b"}) {
		t.Errorf("env: %v %v", paths, isDefault)
	}

	paths, isDefault, _ = Resolve([]string{"/c"})
	if isDefault || !slices.Equal(paths, []string{"/c"}) {
		t.Errorf("flag should beat env: %v %v", paths, isDefault)
	}
}
