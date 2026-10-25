// Package cli implements the password-cleaner command line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Exit codes.
const (
	exitOK      = 0
	exitMatches = 1 // --check found a secret
	exitError   = 2
)

// BuildInfo describes the running binary. It is filled in at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

func (b BuildInfo) String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", b.Version, b.Commit, b.Date)
}

// errMatches is returned by --check when a secret was found. It is not
// reported to the user: the matches themselves are the output.
var errMatches = errors.New("secrets found")

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer

	// isTTY reports whether r is an interactive terminal. prompt reads one
	// line from the terminal without echoing it. Tests replace both.
	isTTY  func(r io.Reader) bool
	prompt func(label string) (string, error)
	// now supplies the date written into comments. environFn supplies the
	// environment variables; nil means the real ones.
	now       func() time.Time
	environFn func() []string

	filter  filterFlags
	add     addFlags
	hash    secretFlags
	envList envListFlags
	envAdd  envAddFlags
}

func newApp(stdin io.Reader, stdout, stderr io.Writer) *app {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr, isTTY: isTerminal, now: time.Now}
	a.prompt = func(label string) (string, error) {
		_, _ = fmt.Fprint(stderr, label)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(stderr)
		return string(b), err
	}
	return a
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

const rootLong = `password-cleaner removes secrets from text.

It reads lines from the given files, or from standard input, and drops (or
redacts) every line that contains a secret. The secrets themselves are never
stored: you keep a file of their SHA-256 hashes, and every substring of each
line is hashed and looked up in it.

The default hash file is password-cleaner/hashes.txt in your config directory.
Use --hash-file (repeatable) or $PASSWORD_CLEANER_HASH_FILE to use others.
Add secrets to it with "password-cleaner add", or import them from your
environment variables with "password-cleaner env add". With --env, secrets in
environment variables (TOKEN, SECRET, PASSWORD and similar) are used for the
run without being stored.

Exit status: 0 on success, 1 if --check found a secret, 2 on any error.`

const rootExample = `  # Drop every line that contains a known secret
  cat shell-history | password-cleaner > cleaned

  # Keep the lines, but blank out the secrets
  password-cleaner --redact app.log > app.clean.log

  # Fail a CI job or pre-commit hook if a file contains a secret
  password-cleaner --check config.yaml

  # Also treat secrets in environment variables as secrets, without saving them
  password-cleaner --env --redact app.log

  # Remember a new secret (prompts without echoing it)
  password-cleaner add

  # Pick secrets out of your environment to remember, confirming each one
  password-cleaner env add`

func newRoot(a *app, info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "password-cleaner [flags] [file...]",
		Short:         "Remove lines containing known secrets from text",
		Long:          rootLong,
		Example:       rootExample,
		Version:       info.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE:          a.runFilter,
	}
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.CompletionOptions.DisableDefaultCmd = true

	a.filter.register(root)
	root.AddCommand(a.addCmd(), a.hashCmd(), a.envCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(info BuildInfo, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return newApp(stdin, stdout, stderr).execute(info, args)
}

func (a *app) execute(info BuildInfo, args []string) int {
	root := newRoot(a, info)
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errMatches):
		return exitMatches
	default:
		_, _ = fmt.Fprintf(a.stderr, "password-cleaner: %v\n", err)
		return exitError
	}
}

func (a *app) warnf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.stderr, "password-cleaner: warning: "+format+"\n", args...)
}
