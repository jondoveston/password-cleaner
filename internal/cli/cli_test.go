package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jondoveston/password-cleaner/internal/hashes"
)

var testInfo = BuildInfo{Version: "1.2.3", Commit: "abc1234", Date: "2026-01-02T03:04:05Z"}

// harness isolates a test from the real config directory and environment.
type harness struct {
	t       *testing.T
	config  string // XDG_CONFIG_HOME
	tty     bool
	prompts []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, config: t.TempDir()}
	t.Setenv("XDG_CONFIG_HOME", h.config)
	t.Setenv(hashes.EnvVar, "")
	return h
}

func (h *harness) defaultFile() string {
	return filepath.Join(h.config, "password-cleaner", "hashes.txt")
}

// writeHashes writes a hash file containing the given secrets and returns its path.
func (h *harness) writeHashes(path string, secrets ...string) string {
	h.t.Helper()
	var sb strings.Builder
	for _, s := range secrets {
		sb.WriteString(hashes.New(s).String() + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return path
}

func (h *harness) run(stdin string, args ...string) (stdout, stderr string, code int) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(stdin), &out, &errOut)
	a.isTTY = func(io.Reader) bool { return h.tty }
	a.prompt = func(string) (string, error) {
		if len(h.prompts) == 0 {
			return "", errors.New("unexpected prompt")
		}
		p := h.prompts[0]
		h.prompts = h.prompts[1:]
		return p, nil
	}
	code = a.execute(testInfo, args)
	return out.String(), errOut.String(), code
}

func TestVersion(t *testing.T) {
	out, _, code := newHarness(t).run("", "--version")
	if code != 0 || out != "password-cleaner 1.2.3 (commit abc1234, built 2026-01-02T03:04:05Z)\n" {
		t.Errorf("got %q (%d)", out, code)
	}
}

func TestHelp(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.run("", "--help")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"--hash-file", "--on-match", "--redact", "--check", "add", "hash", "Exit status"} {
		if !strings.Contains(out, want) {
			t.Errorf("help does not mention %q", want)
		}
	}
	out, _, _ = h.run("", "add", "--help")
	if !strings.Contains(out, "--comment") || !strings.Contains(out, "--force") {
		t.Errorf("add help: %s", out)
	}
}

func TestFilterDropsByDefault(t *testing.T) {
	h := newHarness(t)
	h.writeHashes(h.defaultFile(), "hunter22")

	out, errOut, code := h.run("one\nmy hunter22 pw\ntwo\n")
	if code != 0 || out != "one\ntwo\n" {
		t.Errorf("out=%q code=%d", out, code)
	}
	if errOut != "" {
		t.Errorf("should be silent by default, stderr = %q", errOut)
	}
	if strings.Contains(out+errOut, "hunter22") {
		t.Error("the secret leaked")
	}
}

func TestFilterRedact(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")

	for _, args := range [][]string{{"--redact"}, {"-r"}, {"--on-match", "redact"}} {
		out, _, code := h.run("pw hunter22!\n", append([]string{"-f", file}, args...)...)
		if code != 0 || out != "pw [REDACTED]!\n" {
			t.Errorf("%v: out=%q code=%d", args, out, code)
		}
	}
	out, _, _ := h.run("pw hunter22!\n", "-f", file, "-r", "--replacement", "***")
	if out != "pw ***!\n" {
		t.Errorf("replacement: %q", out)
	}
}

func TestFilterStderrMode(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")
	out, errOut, code := h.run("a\nhunter22\nb\n", "-f", file, "--on-match", "stderr")
	if code != 0 || out != "a\nb\n" || errOut != "hunter22\n" {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}
}

func TestCheck(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")

	out, errOut, code := h.run("a\nhunter22\nb\nxx hunter22\n", "-f", file, "--check")
	if code != 1 || out != "<stdin>:2\n<stdin>:4\n" || errOut != "" {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}

	out, errOut, code = h.run("all clean\n", "-f", file, "--check")
	if code != 0 || out != "" || errOut != "" {
		t.Errorf("clean: out=%q err=%q code=%d", out, errOut, code)
	}

	// Named files are labelled by name, and nothing of the line is printed.
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.txt"), filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(good, []byte("fine\n"), 0o600)
	_ = os.WriteFile(bad, []byte("fine\nhunter22\n"), 0o600)
	out, _, code = h.run("", "-f", file, "-c", good, bad)
	if code != 1 || out != bad+":2\n" {
		t.Errorf("files: out=%q code=%d", out, code)
	}
}

func TestCheckWithNoHashesIsAnError(t *testing.T) {
	h := newHarness(t)
	empty := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	_, errOut, code := h.run("x\n", "-f", empty, "--check")
	if code != 2 || !strings.Contains(errOut, "nothing to check against") {
		t.Errorf("err=%q code=%d", errOut, code)
	}
}

func TestEmptyHashFileWarnsAndPassesThrough(t *testing.T) {
	h := newHarness(t)
	empty := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(empty, nil, 0o600)
	out, errOut, code := h.run("x\ny\n", "-f", empty)
	if code != 0 || out != "x\ny\n" || !strings.Contains(errOut, "no hashes loaded") {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}
}

func TestMultipleHashFiles(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	one := h.writeHashes(filepath.Join(dir, "one.txt"), "hunter22")
	two := h.writeHashes(filepath.Join(dir, "two.txt"), "correct horse")

	out, _, _ := h.run("hunter22\ncorrect horse\nfine\n", "-f", one, "-f", two)
	if out != "fine\n" {
		t.Errorf("flags: %q", out)
	}

	t.Setenv(hashes.EnvVar, one+string(os.PathListSeparator)+two)
	out, _, _ = h.run("hunter22\ncorrect horse\nfine\n")
	if out != "fine\n" {
		t.Errorf("env: %q", out)
	}

	// The flag beats the environment.
	out, _, _ = h.run("hunter22\ncorrect horse\nfine\n", "-f", two)
	if out != "hunter22\nfine\n" {
		t.Errorf("flag over env: %q", out)
	}
}

func TestFilterFiles(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.WriteFile(a, []byte("a1\nhunter22\n"), 0o600)
	_ = os.WriteFile(b, []byte("b1\n"), 0o600)

	out, _, code := h.run("from stdin\n", "-f", file, a, "-", b)
	if code != 0 || out != "a1\nfrom stdin\nb1\n" {
		t.Errorf("out=%q code=%d", out, code)
	}

	_, errOut, code := h.run("", "-f", file, filepath.Join(dir, "missing"))
	if code != 2 || !strings.Contains(errOut, "missing") {
		t.Errorf("missing input: err=%q code=%d", errOut, code)
	}
}

func TestMissingDefaultHashFileExplainsHowToCreateIt(t *testing.T) {
	h := newHarness(t)
	_, errOut, code := h.run("x\n")
	if code != 2 || !strings.Contains(errOut, "password-cleaner add") || !strings.Contains(errOut, h.defaultFile()) {
		t.Errorf("err=%q code=%d", errOut, code)
	}
	_, errOut, code = h.run("x\n", "-f", "/nonexistent/hashes.txt")
	if code != 2 || !strings.Contains(errOut, "hash file not found: /nonexistent/hashes.txt") {
		t.Errorf("explicit: err=%q code=%d", errOut, code)
	}
}

func TestVerbose(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22", "other secret")
	_, errOut, _ := h.run("a\nhunter22\n", "-f", file, "-v")
	if !strings.Contains(errOut, "loaded 2 hashes from "+file) || !strings.Contains(errOut, "1 of 2 lines dropped") {
		t.Errorf("err=%q", errOut)
	}
}

func TestMalformedHashLinesWarnWithoutLeaking(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "h.txt")
	_ = os.WriteFile(file, []byte("oops-a-pasted-secret\n"+hashes.New("hunter22").String()+"\n"), 0o600)
	out, errOut, code := h.run("hunter22\nfine\n", "-f", file)
	if code != 0 || out != "fine\n" {
		t.Errorf("out=%q code=%d", out, code)
	}
	if !strings.Contains(errOut, file+":1:") || strings.Contains(errOut, "pasted-secret") {
		t.Errorf("err=%q", errOut)
	}
}

func TestBareHashesStillWork(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "h.txt")
	e := hashes.New("hunter22")
	_ = os.WriteFile(file, []byte(e.Sum.String()+"\n"), 0o600)

	out, _, _ := h.run("x hunter22 y\nfine\n", "-f", file)
	if out != "fine\n" {
		t.Errorf("out=%q", out)
	}
	// Shorter than --min-length: not found, unless the limit is lowered.
	_ = os.WriteFile(file, []byte(hashes.Hash([]byte("abcd")).String()+"\n"), 0o600)
	out, _, _ = h.run("abcd\n", "-f", file)
	if out != "abcd\n" {
		t.Errorf("below min length: %q", out)
	}
	out, _, _ = h.run("abcd\n", "-f", file, "--min-length", "4")
	if out != "" {
		t.Errorf("lowered min length: %q", out)
	}
}

func TestFlagErrors(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"bad mode", []string{"--on-match", "explode"}, "invalid --on-match"},
		{"min length", []string{"--min-length", "0"}, "--min-length must be at least 1"},
		{"replacement without redact", []string{"--replacement", "x"}, "--replacement only makes sense"},
		{"redact and on-match", []string{"-r", "--on-match", "drop"}, "none of the others can be"},
		{"check and redact", []string{"-c", "-r"}, "none of the others can be"},
		{"unknown flag", []string{"--bogus"}, "unknown flag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, errOut, code := h.run("x\n", append([]string{"-f", file}, tc.args...)...)
			if code != 2 || !strings.Contains(errOut, tc.want) {
				t.Errorf("err=%q code=%d", errOut, code)
			}
		})
	}
}

func TestNoInputOnTerminal(t *testing.T) {
	h := newHarness(t)
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "hunter22")
	h.tty = true
	_, errOut, code := h.run("", "-f", file)
	if code != 2 || !strings.Contains(errOut, "no input") {
		t.Errorf("err=%q code=%d", errOut, code)
	}
}

func TestAddFromPipe(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.run("hunter22\n\ncorrect horse\r\nhunter22\n", "add", "--comment", "test")
	if code != 0 || !strings.Contains(out, "added 2 hash(es) to "+h.defaultFile()) || !strings.Contains(out, "1 already present") {
		t.Errorf("out=%q code=%d", out, code)
	}
	data, err := os.ReadFile(h.defaultFile())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hunter22") || strings.Contains(string(data), "horse") {
		t.Error("the secret was written in the clear")
	}
	for _, want := range []string{hashes.New("hunter22").Sum.String(), "13:" + hashes.New("correct horse").Sum.String(), "# test"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("hash file lacks %q:\n%s", want, data)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(h.defaultFile())
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", info.Mode().Perm())
		}
	}

	// And the new file works for filtering.
	filtered, _, _ := h.run("fine\nthe hunter22 one\n")
	if filtered != "fine\n" {
		t.Errorf("filtered = %q", filtered)
	}
}

func TestAddUpgradesBareHashes(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "h.txt")
	bare := hashes.New("hunter22").Sum.String()
	_ = os.WriteFile(file, []byte("# mine\n"+bare+"  # work\n"), 0o600)

	out, _, code := h.run("hunter22\nsomething else\n", "add", "-f", file)
	if code != 0 || !strings.Contains(out, "added 1 hash(es)") || !strings.Contains(out, "upgraded 1 to include the length") {
		t.Errorf("out=%q code=%d", out, code)
	}
	data, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(data), "# mine\n8:"+bare+"  # work\n") {
		t.Errorf("file:\n%s", data)
	}

	other := filepath.Join(t.TempDir(), "o.txt")
	_ = os.WriteFile(other, []byte(bare+"\n"), 0o600)
	out, _, _ = h.run("hunter22\n", "add", "-f", other)
	if !strings.HasPrefix(out, "upgraded 1 hash(es) in "+other+" to include the length") {
		t.Errorf("upgrade only: %q", out)
	}

	out, _, _ = h.run("hunter22\n", "add", "-f", file)
	if !strings.Contains(out, "added 0 hash(es)") || !strings.Contains(out, "1 already present") || strings.Contains(out, "upgraded") {
		t.Errorf("second run: %q", out)
	}
}

func TestAddToChosenFile(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "mine.txt")
	_, _, code := h.run("hunter22\n", "add", "-f", file)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(file); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(h.defaultFile()); err == nil {
		t.Error("the default file should not have been created")
	}
}

func TestAddFromTerminal(t *testing.T) {
	h := newHarness(t)
	h.tty = true

	h.prompts = []string{"hunter22", "hunter22"}
	out, _, code := h.run("", "add")
	if code != 0 || !strings.Contains(out, "added 1 hash(es)") {
		t.Errorf("out=%q code=%d", out, code)
	}

	h.prompts = []string{"hunter22", "different"}
	_, errOut, code := h.run("", "add")
	if code != 2 || !strings.Contains(errOut, "do not match") {
		t.Errorf("mismatch: err=%q code=%d", errOut, code)
	}

	h.prompts = []string{""}
	_, errOut, code = h.run("", "add")
	if code != 2 || !strings.Contains(errOut, "empty") {
		t.Errorf("empty: err=%q code=%d", errOut, code)
	}
}

func TestAddRejectsShortSecrets(t *testing.T) {
	h := newHarness(t)

	_, errOut, code := h.run("abc\n", "add")
	if code != 2 || !strings.Contains(errOut, "--force") || strings.Contains(errOut, "abc\n") {
		t.Errorf("err=%q code=%d", errOut, code)
	}
	if _, err := os.Stat(h.defaultFile()); err == nil {
		t.Error("nothing should have been written")
	}

	// One bad secret stops the whole batch.
	_, errOut, code = h.run("hunter22\nabc\n", "add")
	if code != 2 || !strings.Contains(errOut, "secret 2") {
		t.Errorf("batch: err=%q code=%d", errOut, code)
	}
	if _, err := os.Stat(h.defaultFile()); err == nil {
		t.Error("nothing should have been written for a rejected batch")
	}

	_, errOut, code = h.run("abc\n", "add", "--force")
	if code != 0 || !strings.Contains(errOut, "only 3 characters") {
		t.Errorf("forced: err=%q code=%d", errOut, code)
	}
}

func TestAddWarnsAboutShortSecrets(t *testing.T) {
	h := newHarness(t)
	_, errOut, code := h.run("abcdef\n", "add")
	if code != 0 || !strings.Contains(errOut, "warning") || !strings.Contains(errOut, "only 6 characters") {
		t.Errorf("err=%q code=%d", errOut, code)
	}
	_, errOut, _ = h.run("a long enough one\n", "add")
	if errOut != "" {
		t.Errorf("no warning expected: %q", errOut)
	}
}

func TestAddErrors(t *testing.T) {
	h := newHarness(t)
	if _, errOut, code := h.run("", "add"); code != 2 || !strings.Contains(errOut, "no secrets") {
		t.Errorf("empty stdin: err=%q code=%d", errOut, code)
	}
	if _, errOut, code := h.run("hunter22\n", "add", "--comment", "a\nb"); code != 2 || !strings.Contains(errOut, "single line") {
		t.Errorf("comment: err=%q code=%d", errOut, code)
	}
	t.Setenv(hashes.EnvVar, "/a"+string(os.PathListSeparator)+"/b")
	if _, errOut, code := h.run("hunter22\n", "add"); code != 2 || !strings.Contains(errOut, "choose one with --hash-file") {
		t.Errorf("several env files: err=%q code=%d", errOut, code)
	}
	if _, _, code := h.run("hunter22\n", "add", "extra"); code != 2 {
		t.Errorf("positional arg: code=%d", code)
	}
}

func TestHash(t *testing.T) {
	h := newHarness(t)
	out, _, code := h.run("password\n", "hash", "--comment", "bank")
	want := "8:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  # bank\n"
	if code != 0 || out != want {
		t.Errorf("out=%q code=%d", out, code)
	}
	if _, err := os.Stat(h.defaultFile()); err == nil {
		t.Error("hash must not write the hash file")
	}
	if _, errOut, code := h.run("abc\n", "hash"); code != 2 || !strings.Contains(errOut, "--force") {
		t.Errorf("short: err=%q code=%d", errOut, code)
	}
}
