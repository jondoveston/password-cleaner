package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/jondoveston/password-cleaner/internal/cleaner"
	"github.com/jondoveston/password-cleaner/internal/hashes"
)

type filterFlags struct {
	envOpts
	env         bool
	hashFiles   []string
	onMatch     string
	redact      bool
	replacement string
	check       bool
	minLength   int
	verbose     bool
}

func (f *filterFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringArrayVarP(&f.hashFiles, "hash-file", "f", nil,
		"file of secret hashes; repeat to use several (default: $"+hashes.EnvVar+", then the config directory)")
	fl.StringVar(&f.onMatch, "on-match", "drop",
		"what to do with a line containing a secret: drop, redact or stderr\n"+
			"(stderr prints the whole line, secret included, to standard error)")
	fl.BoolVarP(&f.redact, "redact", "r", false, "shorthand for --on-match redact")
	fl.StringVar(&f.replacement, "replacement", "[REDACTED]", "text that --redact puts in place of a secret")
	fl.BoolVarP(&f.check, "check", "c", false,
		"print FILE:LINE for each line containing a secret instead of filtering; exit 1 if there were any")
	fl.IntVar(&f.minLength, "min-length", 8,
		"shortest substring to try for bare hashes (hashes without a length prefix)")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "report which hash files are used and what was removed")
	fl.BoolVar(&f.env, "env", false,
		"also treat the values of secret-looking environment variables (TOKEN, SECRET, PASSWORD, ...) as secrets;\n"+
			"they are used in memory only and never saved")
	f.envOpts.register(fl)
	cmd.MarkFlagsMutuallyExclusive("check", "on-match", "redact")
	cmd.MarkFlagsMutuallyExclusive("on-match", "redact")
}

func (f *filterFlags) mode() (cleaner.Mode, error) {
	if f.redact {
		return cleaner.Redact, nil
	}
	switch f.onMatch {
	case "drop":
		return cleaner.Drop, nil
	case "redact":
		return cleaner.Redact, nil
	case "stderr":
		return cleaner.Stderr, nil
	}
	return 0, fmt.Errorf("invalid --on-match %q: use drop, redact or stderr", f.onMatch)
}

func (a *app) runFilter(cmd *cobra.Command, files []string) error {
	f := &a.filter
	mode, err := f.mode()
	if err != nil {
		return err
	}
	if f.minLength < 1 {
		return errors.New("--min-length must be at least 1")
	}
	if cmd.Flags().Changed("replacement") && mode != cleaner.Redact {
		return errors.New("--replacement only makes sense with --redact")
	}

	set, err := a.loadSet()
	if err != nil {
		return err
	}
	if f.env {
		if err := a.addEnvSecrets(set); err != nil {
			return err
		}
	}
	switch {
	case set.Len() == 0 && f.check:
		return errors.New("no hashes loaded, so there is nothing to check against")
	case set.Len() == 0:
		a.warnf("no hashes loaded; input is passed through unchanged")
	}

	if len(files) == 0 {
		if a.isTTY(a.stdin) {
			return errors.New("no input: pipe text into password-cleaner or name files (see --help)")
		}
		files = []string{"-"}
	}

	var stats cleaner.Stats
	for _, name := range files {
		display := name
		if name == "-" {
			display = "<stdin>"
		}
		opts := cleaner.Options{
			Set:         set,
			MinLength:   f.minLength,
			Mode:        mode,
			Replacement: f.replacement,
			Check:       f.check,
		}
		if f.check {
			opts.OnMatch = func(line int) { _, _ = fmt.Fprintf(a.stdout, "%s:%d\n", display, line) }
		}

		s, err := a.filterOne(name, opts)
		stats.Lines += s.Lines
		stats.Matched += s.Matched
		if err != nil {
			return err
		}
	}

	if f.verbose {
		verb := map[cleaner.Mode]string{cleaner.Drop: "dropped", cleaner.Redact: "redacted", cleaner.Stderr: "diverted to stderr"}[mode]
		if f.check {
			verb = "matched"
		}
		_, _ = fmt.Fprintf(a.stderr, "password-cleaner: %d of %d lines %s\n", stats.Matched, stats.Lines, verb)
	}
	if f.check && stats.Matched > 0 {
		return errMatches
	}
	return nil
}

// filterOne runs the filter over a single named input ("-" is stdin).
func (a *app) filterOne(name string, opts cleaner.Options) (cleaner.Stats, error) {
	in := a.stdin
	if name != "-" {
		file, err := os.Open(name)
		if err != nil {
			return cleaner.Stats{}, err
		}
		defer func() { _ = file.Close() }()
		in = file
	}
	return cleaner.Filter(in, a.stdout, a.stderr, opts)
}

// loadSet reads every configured hash file into one set.
func (a *app) loadSet() (*hashes.Set, error) {
	paths, isDefault, err := hashes.Resolve(a.filter.hashFiles)
	if err != nil {
		return nil, err
	}
	set := hashes.NewSet()
	for _, p := range paths {
		n, err := set.LoadFile(p, func(msg string) { a.warnf("%s", msg) })
		if errors.Is(err, fs.ErrNotExist) {
			if isDefault && a.filter.env {
				// Environment variables can be the only source of secrets.
				if a.filter.verbose {
					_, _ = fmt.Fprintf(a.stderr, "password-cleaner: no hash file at %s; using environment variables only\n", p)
				}
				continue
			}
			if isDefault {
				return nil, fmt.Errorf("no hash file at %s\n\n"+
					"Add a secret to create it:\n  password-cleaner add\n\n"+
					"or use another file with --hash-file or $%s", p, hashes.EnvVar)
			}
			return nil, fmt.Errorf("hash file not found: %s", p)
		}
		if err != nil {
			return nil, err
		}
		if a.filter.verbose {
			_, _ = fmt.Fprintf(a.stderr, "password-cleaner: loaded %d hashes from %s\n", n, p)
		}
	}
	return set, nil
}
