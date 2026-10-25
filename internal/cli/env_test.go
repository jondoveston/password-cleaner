package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jondoveston/password-cleaner/internal/hashes"
)

const (
	ghToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	awsKey  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// envFile returns the path of a not-yet-existing hash file in a temp dir.
func envFile(t *testing.T) string { return filepath.Join(t.TempDir(), "hashes.txt") }

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func noValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, secret := range []string{ghToken, awsKey, "hunter22"} {
			if strings.Contains(o, secret) {
				t.Errorf("a secret value appeared in the output: %q", o)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// --env while filtering

func TestFilterEnv(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "HOME=/home/me", "EDITOR=vim"}
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "something else")
	input := "start\nthe token is " + ghToken + " ok\nend\n"

	out, _, code := h.run(input, "-f", file)
	if code != 0 || out != input {
		t.Errorf("without --env nothing should be removed: out=%q", out)
	}

	out, errOut, code := h.run(input, "-f", file, "--env")
	if code != 0 || out != "start\nend\n" {
		t.Errorf("out=%q code=%d", out, code)
	}
	noValues(t, out, errOut)

	out, _, _ = h.run(input, "-f", file, "--env", "--redact")
	if out != "start\nthe token is [REDACTED] ok\nend\n" {
		t.Errorf("redact: %q", out)
	}

	out, _, code = h.run(input, "-f", file, "--env", "--check")
	if code != 1 || out != "<stdin>:2\n" {
		t.Errorf("check: out=%q code=%d", out, code)
	}
}

func TestFilterEnvNeedsNoHashFile(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}
	input := "a\n" + ghToken + "\n"

	out, errOut, code := h.run(input, "--env")
	if code != 0 || out != "a\n" || errOut != "" {
		t.Errorf("missing default file: out=%q err=%q code=%d", out, errOut, code)
	}
	// A hash file named explicitly must still exist.
	_, errOut, code = h.run(input, "--env", "-f", "/nonexistent/h.txt")
	if code != 2 || !strings.Contains(errOut, "hash file not found") {
		t.Errorf("explicit file: err=%q code=%d", errOut, code)
	}
	// Without --env the missing default file is still an error.
	_, _, code = h.run(input)
	if code != 2 {
		t.Errorf("no --env: code=%d", code)
	}
}

func TestFilterEnvUsesNarrowPatterns(t *testing.T) {
	h := newHarness(t)
	h.env = []string{
		"OPENAI_KEY=sk-proj-0123456789",
		"KEYTIMEOUT=0123456789",
		"GPG_KEY_ID=ABCDEF0123456789",
		"SSH_AUTH_SOCK=/tmp/agent.12345",
	}
	input := "sk-proj-0123456789\n0123456789\nABCDEF0123456789\n/tmp/agent.12345\n"
	out, _, _ := h.run(input, "--env")
	// Only OPENAI_KEY (which ends in _KEY) is used; the other names are not
	// narrow matches, so their values are kept.
	if out != "0123456789\nABCDEF0123456789\n/tmp/agent.12345\n" {
		t.Errorf("out=%q", out)
	}
}

func TestFilterEnvPatternOptions(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"MYCO_THING=my-company-thing", "GITHUB_TOKEN=" + ghToken}
	input := "my-company-thing\n" + ghToken + "\nplain\n"

	out, _, _ := h.run(input, "--env", "--env-var", "MYCO_*")
	if out != ghToken+"\nplain\n" {
		t.Errorf("--env-var replaces the defaults: %q", out)
	}
	// Excluding keeps the default patterns: MYCO_THING is not among them.
	out, _, _ = h.run(input, "--env", "--env-exclude", "github_*")
	if out != input {
		t.Errorf("--env-exclude: %q", out)
	}

	h.env = append(h.env, "PASSWORD_CLEANER_ENV_VARS=myco_*", "PASSWORD_CLEANER_ENV_EXCLUDE=nothing")
	out, _, _ = h.run(input, "--env")
	if out != ghToken+"\nplain\n" {
		t.Errorf("environment settings: %q", out)
	}
	out, _, _ = h.run(input, "--env", "--env-var", "GITHUB_*")
	if out != "my-company-thing\nplain\n" {
		t.Errorf("flags beat the environment: %q", out)
	}

	_, errOut, code := h.run(input, "--env", "--env-var", "[bad")
	if code != 2 || !strings.Contains(errOut, "invalid pattern") {
		t.Errorf("bad pattern: err=%q code=%d", errOut, code)
	}
}

func TestFilterEnvSkipsShortAndMultilineValues(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"DEBUG_TOKEN=1", "EMPTY_TOKEN=", "PEM_SECRET=line one\nline two", "OK_TOKEN=a-real-token"}
	input := "1\nline one\na-real-token\nfine\n"
	out, errOut, _ := h.run(input, "--env", "-v")
	if out != "1\nline one\nfine\n" {
		t.Errorf("out=%q", out)
	}
	for _, want := range []string{"using 1 environment variable(s): OK_TOKEN", "ignoring $DEBUG_TOKEN: too short", "ignoring $PEM_SECRET: multi-line"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
}

func TestFilterEnvVerboseNamesOnly(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}
	_, errOut, _ := h.run("x\n", "--env", "-v")
	noValues(t, errOut)
	if !strings.Contains(errOut, "GITHUB_TOKEN") {
		t.Errorf("err=%q", errOut)
	}
}

// ---------------------------------------------------------------------------
// env list

func TestEnvList(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "h.txt")
	bareOnly := hashes.Hash([]byte("bare-secret-value")).String()
	_ = os.WriteFile(file, []byte(
		hashes.New(awsKey).String()+"\n"+bareOnly+"\n"), 0o600)
	h.env = []string{
		"GITHUB_TOKEN=" + ghToken,
		"AWS_SECRET_ACCESS_KEY=" + awsKey,
		"OLD_SECRET=bare-secret-value",
		"DEBUG_KEY=1",
		"PEM_PRIVATE_KEY=a\nb",
		"HOME=/home/me",
		"EMPTY_TOKEN=",
		"PASSWORD_CLEANER_ENV_VARS=",
	}
	out, errOut, code := h.run("", "env", "list", "-f", file)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	noValues(t, out, errOut)
	for _, want := range []string{
		"NAME", "LENGTH", "STATUS",
		"AWS_SECRET_ACCESS_KEY  40      in hash file",
		"DEBUG_KEY              1       too short, skipped",
		"GITHUB_TOKEN           40      new",
		"OLD_SECRET             17      bare hash, add will upgrade it",
		"PEM_PRIVATE_KEY        3       multi-line, skipped",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"HOME", "EMPTY_TOKEN", "PASSWORD_CLEANER"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output should not mention %q:\n%s", unwanted, out)
		}
	}
}

func TestEnvListNarrow(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "KEYTIMEOUT=0123456789"}
	file := h.writeHashes(filepath.Join(t.TempDir(), "h.txt"), "x-unrelated")
	out, _, _ := h.run("", "env", "list", "-f", file)
	if !strings.Contains(out, "KEYTIMEOUT") {
		t.Errorf("broad list should include KEYTIMEOUT:\n%s", out)
	}
	out, _, _ = h.run("", "env", "list", "-f", file, "--narrow")
	if strings.Contains(out, "KEYTIMEOUT") || !strings.Contains(out, "GITHUB_TOKEN") {
		t.Errorf("narrow list:\n%s", out)
	}
}

func TestEnvListNeedsNoHashFile(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}
	out, _, code := h.run("", "env", "list")
	if code != 0 || !strings.Contains(out, "GITHUB_TOKEN") || !strings.Contains(out, "new") {
		t.Errorf("out=%q code=%d", out, code)
	}
}

func TestEnvListNothingMatches(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"HOME=/home/me"}
	out, errOut, code := h.run("", "env", "list")
	if code != 0 || out != "" || !strings.Contains(errOut, "no environment variables match") {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}
}

func TestEnvWithoutSubcommandShowsHelp(t *testing.T) {
	out, _, code := newHarness(t).run("", "env")
	if code != 0 || !strings.Contains(out, "list") || !strings.Contains(out, "add") {
		t.Errorf("out=%q code=%d", out, code)
	}
}

// ---------------------------------------------------------------------------
// env add

func TestEnvAddAsksAndAdds(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "AWS_SECRET_ACCESS_KEY=" + awsKey, "HOME=/home/me"}
	file := envFile(t)

	// Answers come from stdin; the questions go to stderr.
	out, errOut, code := h.run("y\nn\n", "env", "add", "-f", file)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	noValues(t, out, errOut)
	if !strings.Contains(errOut, "Add AWS_SECRET_ACCESS_KEY (40 characters)? [y/N/a/q]") ||
		!strings.Contains(errOut, "Add GITHUB_TOKEN (40 characters)? [y/N/a/q]") {
		t.Errorf("prompts: %q", errOut)
	}
	if !strings.Contains(out, "added 1 hash(es), 1 declined; hash file: "+file) {
		t.Errorf("summary: %q", out)
	}
	data := readFile(t, file)
	want := "40:" + hashes.New(awsKey).Sum.String() + "  # AWS_SECRET_ACCESS_KEY, added 2026-10-25\n"
	if data != want {
		t.Errorf("file:\n%s\nwant:\n%s", data, want)
	}
	noValues(t, data)
}

func TestEnvAddAnswers(t *testing.T) {
	envs := []string{"A_TOKEN=aaaaaaaa", "B_TOKEN=bbbbbbbb", "C_TOKEN=cccccccc", "D_TOKEN=dddddddd"}
	has := func(data, secret string) bool { return strings.Contains(data, hashes.New(secret).Sum.String()) }
	tests := []struct {
		name    string
		stdin   string
		want    [4]bool // A, B, C, D added
		wantErr string
	}{
		{"all yes", "y\ny\ny\ny\n", [4]bool{true, true, true, true}, ""},
		{"all no", "n\nn\nn\nn\n", [4]bool{}, ""},
		{"default is no", "\n\n\n\n", [4]bool{}, ""},
		{"full words", "yes\nno\nYES\nNo\n", [4]bool{true, false, true, false}, ""},
		{"all", "n\na\n", [4]bool{false, true, true, true}, ""},
		{"quit keeps earlier yeses", "y\nq\n", [4]bool{true, false, false, false}, ""},
		{"end of input quits", "y\ny\n", [4]bool{true, true, false, false}, ""},
		{"retries after a bad answer", "maybe\ny\nn\nn\nn\n", [4]bool{true, false, false, false}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.tty = true
			h.env = envs
			file := envFile(t)
			_, errOut, code := h.run(tc.stdin, "env", "add", "-f", file)
			if code != 0 {
				t.Fatalf("code=%d err=%s", code, errOut)
			}
			data := ""
			if _, err := os.Stat(file); err == nil {
				data = readFile(t, file)
			}
			for i, secret := range []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"} {
				if has(data, secret) != tc.want[i] {
					t.Errorf("%c_TOKEN added = %v, want %v\nfile:\n%s", 'A'+i, has(data, secret), tc.want[i], data)
				}
			}
		})
	}
}

func TestEnvAddSkipsWhatIsAlreadyThere(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	file := filepath.Join(t.TempDir(), "h.txt")
	_ = os.WriteFile(file, []byte(hashes.New(ghToken).String()+"  # something I added by hand\n"), 0o600)
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "RENAMED_TOKEN=" + ghToken}

	// No questions are asked, so there is nothing to answer.
	out, errOut, code := h.run("", "env", "add", "-f", file, "-v")
	if code != 0 || !strings.Contains(out, "nothing to add: 2 already in the hash file") {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}
	if strings.Contains(errOut, "Add ") {
		t.Errorf("should not have asked: %q", errOut)
	}
	// It is the value that counts, not the name or the comment.
	for _, want := range []string{"skipped GITHUB_TOKEN: in hash file", "skipped RENAMED_TOKEN: in hash file"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("verbose output lacks %q:\n%s", want, errOut)
		}
	}
	if got := readFile(t, file); !strings.HasSuffix(got, "# something I added by hand\n") || strings.Count(got, "\n") != 1 {
		t.Errorf("file changed:\n%s", got)
	}
}

func TestEnvAddChecksEveryHashFile(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	second := h.writeHashes(filepath.Join(dir, "second.txt"), ghToken)
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "OTHER_TOKEN=another-token-value"}

	out, errOut, code := h.run("y\n", "env", "add", "-f", first, "-f", second)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	if strings.Contains(errOut, "GITHUB_TOKEN") {
		t.Errorf("a secret kept in the second file should not be offered: %q", errOut)
	}
	if !strings.Contains(out, "1 already in the hash file") {
		t.Errorf("out=%q", out)
	}
	data := readFile(t, first)
	if strings.Contains(data, hashes.New(ghToken).Sum.String()) || !strings.Contains(data, hashes.New("another-token-value").Sum.String()) {
		t.Errorf("new hashes go to the first file only:\n%s", data)
	}
}

func TestEnvAddUpgradesBareHashesWithoutAsking(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	file := filepath.Join(t.TempDir(), "h.txt")
	sum := hashes.Hash([]byte(ghToken)).String()
	_ = os.WriteFile(file, []byte("# mine\n"+sum+"  # personal token\n"), 0o600)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}

	out, errOut, code := h.run("", "env", "add", "-f", file)
	if code != 0 || strings.Contains(errOut, "Add ") {
		t.Fatalf("should not ask: out=%q err=%q code=%d", out, errOut, code)
	}
	if !strings.Contains(out, "upgraded 1 to include the length") {
		t.Errorf("out=%q", out)
	}
	if got, want := readFile(t, file), "# mine\n40:"+sum+"  # personal token\n"; got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}

	// With no comment of its own, an upgraded line gets the variable name.
	_ = os.WriteFile(file, []byte(sum+"\n"), 0o600)
	h.run("", "env", "add", "-f", file)
	if got, want := readFile(t, file), "40:"+sum+"  # GITHUB_TOKEN, added 2026-10-25\n"; got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}

func TestEnvAddSameValueAsksOnce(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "GH_TOKEN=" + ghToken, "OTHER_TOKEN=something-else"}
	file := envFile(t)

	_, errOut, code := h.run("y\ny\n", "env", "add", "-f", file)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	if n := strings.Count(errOut, "Add "); n != 2 {
		t.Errorf("asked %d times, want 2:\n%s", n, errOut)
	}
	if !strings.Contains(errOut, "Add GH_TOKEN and GITHUB_TOKEN (same value, 40 characters)?") {
		t.Errorf("prompt:\n%s", errOut)
	}
	if data := readFile(t, file); !strings.Contains(data, "# GH_TOKEN and GITHUB_TOKEN, added 2026-10-25") || strings.Count(data, "\n") != 2 {
		t.Errorf("file:\n%s", data)
	}
}

func TestEnvAddNamedVariables(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "MY_ODDLY_NAMED_THING=an-oddly-named-secret", "OTHER_TOKEN=not-asked-about"}
	file := envFile(t)

	_, errOut, code := h.run("y\ny\n", "env", "add", "-f", file, "MY_ODDLY_NAMED_THING", "GITHUB_TOKEN")
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	data := readFile(t, file)
	if !strings.Contains(data, hashes.New("an-oddly-named-secret").Sum.String()) ||
		!strings.Contains(data, hashes.New(ghToken).Sum.String()) ||
		strings.Contains(data, hashes.New("not-asked-about").Sum.String()) {
		t.Errorf("file:\n%s", data)
	}

	_, errOut, code = h.run("", "env", "add", "-f", file, "NOT_SET")
	if code != 2 || !strings.Contains(errOut, "$NOT_SET is not set") {
		t.Errorf("unset: err=%q code=%d", errOut, code)
	}
}

func TestEnvAddYes(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"A_TOKEN=aaaaaaaa", "B_TOKEN=bbbbbbbb"}
	file := envFile(t)
	// Works without a terminal, and never reads stdin.
	out, errOut, code := h.run("", "env", "add", "-f", file, "--yes")
	if code != 0 || errOut != "" || !strings.Contains(out, "added 2 hash(es)") {
		t.Errorf("out=%q err=%q code=%d", out, errOut, code)
	}
	if strings.Count(readFile(t, file), "\n") != 2 {
		t.Errorf("file:\n%s", readFile(t, file))
	}
}

func TestEnvAddWithoutTerminalRefusesToGuess(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}
	file := envFile(t)
	_, errOut, code := h.run("y\n", "env", "add", "-f", file)
	if code != 2 || !strings.Contains(errOut, "--yes") {
		t.Errorf("err=%q code=%d", errOut, code)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("nothing should have been written")
	}
}

func TestEnvAddDryRun(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "h.txt")
	_ = os.WriteFile(file, []byte(hashes.New(awsKey).String()+"\n"+hashes.Hash([]byte("old-bare-secret")).String()+"\n"), 0o600)
	before := readFile(t, file)
	h.env = []string{"GITHUB_TOKEN=" + ghToken, "AWS_SECRET_ACCESS_KEY=" + awsKey, "OLD_SECRET=old-bare-secret"}

	// Not a terminal, and no --yes: a dry run neither asks nor refuses.
	out, errOut, code := h.run("", "env", "add", "-f", file, "--dry-run")
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	noValues(t, out, errOut)
	for _, want := range []string{
		"would ask to add GITHUB_TOKEN (40 characters)",
		"would upgrade OLD_SECRET (15 characters)",
		"dry run, nothing written: 1 already in the hash file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if readFile(t, file) != before {
		t.Error("a dry run changed the file")
	}
}

func TestEnvAddSkipsShortAndMultilineValues(t *testing.T) {
	h := newHarness(t)
	h.tty = true
	h.env = []string{"DEBUG_TOKEN=1", "PEM_SECRET=a\nb", "OK_TOKEN=a-real-token"}
	file := envFile(t)
	out, errOut, code := h.run("y\n", "env", "add", "-f", file, "-v")
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	if n := strings.Count(errOut, "Add "); n != 1 {
		t.Errorf("asked %d times:\n%s", n, errOut)
	}
	if !strings.Contains(out, "2 too short or multi-line") ||
		!strings.Contains(errOut, "skipped DEBUG_TOKEN: too short, skipped") ||
		!strings.Contains(errOut, "skipped PEM_SECRET: multi-line, skipped") {
		t.Errorf("out=%q err=%q", out, errOut)
	}
}

func TestEnvAddPatternOptions(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"MYCO_THING=my-company-thing", "GITHUB_TOKEN=" + ghToken}
	file := envFile(t)
	_, _, code := h.run("", "env", "add", "-f", file, "--yes", "--env-var", "MYCO_*")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	data := readFile(t, file)
	if !strings.Contains(data, hashes.New("my-company-thing").Sum.String()) || strings.Contains(data, hashes.New(ghToken).Sum.String()) {
		t.Errorf("file:\n%s", data)
	}
}

func TestEnvAddNoMatches(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"HOME=/home/me"}
	out, _, code := h.run("", "env", "add", "-f", envFile(t), "--yes")
	if code != 0 || !strings.Contains(out, "nothing to add") {
		t.Errorf("out=%q code=%d", out, code)
	}
}

func TestEnvAddUsesDefaultHashFile(t *testing.T) {
	h := newHarness(t)
	h.env = []string{"GITHUB_TOKEN=" + ghToken}
	if _, _, code := h.run("", "env", "add", "--yes"); code != 0 {
		t.Fatal("env add failed")
	}
	if !strings.Contains(readFile(t, h.defaultFile()), "# GITHUB_TOKEN, added 2026-10-25") {
		t.Errorf("file:\n%s", readFile(t, h.defaultFile()))
	}
	// And what it added is then used for filtering.
	out, _, _ := h.run("fine\n" + ghToken + "\n")
	if out != "fine\n" {
		t.Errorf("out=%q", out)
	}
}
