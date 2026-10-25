package cli

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/jondoveston/password-cleaner/internal/hashes"
)

const (
	// minSecretLen is the shortest secret accepted without --force. Anything
	// shorter appears in ordinary text so often that it would wreck the output.
	minSecretLen = 4
	// warnSecretLen is the length below which a secret is accepted with a warning.
	warnSecretLen = 8
)

type secretFlags struct {
	comment string
	force   bool
}

func (s *secretFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&s.comment, "comment", "", "comment stored next to the hash, to remind you what it was (the date is added to it)")
	fl.BoolVar(&s.force, "force", false,
		fmt.Sprintf("accept secrets shorter than %d characters", minSecretLen))
}

type addFlags struct {
	secretFlags
	hashFile string
}

const secretInputHelp = `On a terminal the secret is read without echo and asked for twice. Otherwise
each non-empty line of standard input is a secret, so it never has to appear on
a command line (and so in your shell history or the process list):

  pass show example.com | head -n1 | password-cleaner add`

func (a *app) addCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add secrets to the hash file",
		Long: "Add the hash of one or more secrets to the hash file, creating it if needed.\n" +
			"Secrets already in the file are skipped, except that a bare hash is upgraded\n" +
			"in place to include the secret's length (see the README).\n\n" + secretInputHelp,
		Args: cobra.NoArgs,
		RunE: a.runAdd,
	}
	a.add.register(cmd)
	cmd.Flags().StringVarP(&a.add.hashFile, "hash-file", "f", "",
		"file to add to (default: $"+hashes.EnvVar+", then the config directory)")
	return cmd
}

func (a *app) hashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Print the hash-file line for a secret without saving it",
		Long:  "Print the line that \"add\" would write for each secret.\n\n" + secretInputHelp,
		Args:  cobra.NoArgs,
		RunE:  a.runHash,
	}
	a.hash.register(cmd)
	return cmd
}

func (a *app) runAdd(*cobra.Command, []string) error {
	var explicit []string
	if a.add.hashFile != "" {
		explicit = []string{a.add.hashFile}
	}
	paths, _, err := hashes.Resolve(explicit)
	if err != nil {
		return err
	}
	target := paths[0] // when $PASSWORD_CLEANER_HASH_FILE lists several, the first

	entries, err := a.readEntries(a.add.secretFlags)
	if err != nil {
		return err
	}
	res, err := hashes.Append(target, entries, a.add.comment != "")
	if err != nil {
		return err
	}
	var msg string
	switch {
	case res.Added > 0 && res.Upgraded > 0:
		msg = fmt.Sprintf("added %d hash(es) to %s, upgraded %d to include the length", res.Added, target, res.Upgraded)
	case res.Upgraded > 0:
		msg = fmt.Sprintf("upgraded %d hash(es) in %s to include the length", res.Upgraded, target)
	default:
		msg = fmt.Sprintf("added %d hash(es) to %s", res.Added, target)
	}
	if res.Skipped > 0 {
		msg += fmt.Sprintf(" (%d already present)", res.Skipped)
	}
	_, err = fmt.Fprintln(a.stdout, msg)
	return err
}

func (a *app) runHash(*cobra.Command, []string) error {
	entries, err := a.readEntries(a.hash)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := fmt.Fprintln(a.stdout, e); err != nil {
			return err
		}
	}
	return nil
}

// stamp appends the date to a comment, or makes one if there is none:
// "bank, added 2026-10-25" or "added 2026-10-25".
func (a *app) stamp(comment string) string {
	added := "added " + a.now().Format("2006-01-02")
	if comment == "" {
		return added
	}
	return comment + ", " + added
}

// readEntries reads secrets, checks them and turns them into hash entries.
func (a *app) readEntries(f secretFlags) ([]hashes.Entry, error) {
	if strings.ContainsAny(f.comment, "\r\n") {
		return nil, errors.New("--comment must be a single line")
	}
	secrets, err := a.readSecrets()
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		return nil, errors.New("no secrets given")
	}

	// Check them all before anything is written.
	for i, s := range secrets {
		what := "the secret"
		if len(secrets) > 1 {
			what = fmt.Sprintf("secret %d", i+1)
		}
		n := utf8.RuneCountInString(s)
		switch {
		case n < minSecretLen && !f.force:
			return nil, fmt.Errorf("%s is only %d characters long; it would match far too much text "+
				"(use --force to add it anyway)", what, n)
		case n < warnSecretLen:
			a.warnf("%s is only %d characters long and will match a lot of text", what, n)
		}
	}

	entries := make([]hashes.Entry, len(secrets))
	for i, s := range secrets {
		entries[i] = hashes.New(s)
		entries[i].Comment = a.stamp(f.comment)
	}
	return entries, nil
}

// readSecrets gets secrets from the terminal or, if stdin is piped, from its lines.
func (a *app) readSecrets() ([]string, error) {
	if a.isTTY(a.stdin) {
		first, err := a.prompt("Secret: ")
		if err != nil {
			return nil, err
		}
		if first == "" {
			return nil, errors.New("the secret is empty")
		}
		second, err := a.prompt("Confirm secret: ")
		if err != nil {
			return nil, err
		}
		if first != second {
			return nil, errors.New("the secrets do not match")
		}
		return []string{first}, nil
	}

	var secrets []string
	sc := bufio.NewScanner(a.stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSuffix(sc.Text(), "\r"); line != "" {
			secrets = append(secrets, line)
		}
	}
	return secrets, sc.Err()
}
