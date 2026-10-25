package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jondoveston/password-cleaner/internal/envvars"
	"github.com/jondoveston/password-cleaner/internal/hashes"
)

const (
	// envVarsVar and envExcludeVar set the name patterns for every run.
	envVarsVar    = "PASSWORD_CLEANER_ENV_VARS"
	envExcludeVar = "PASSWORD_CLEANER_ENV_EXCLUDE"
)

// envOpts chooses which environment variables are treated as secrets.
type envOpts struct {
	vars    []string
	exclude []string
}

func (o *envOpts) register(fl *pflag.FlagSet) {
	fl.StringArrayVar(&o.vars, "env-var", nil,
		"glob for names of variables that hold secrets; repeat for several, replaces the defaults\n"+
			"(or set $"+envVarsVar+", comma-separated)")
	fl.StringArrayVar(&o.exclude, "env-exclude", nil,
		"glob for names to leave out; repeat for several (or set $"+envExcludeVar+", comma-separated)")
}

// matcher builds the name matcher: flags win over the environment, which wins
// over the defaults.
func (a *app) envMatcher(o envOpts, defaults []string) (*envvars.Matcher, error) {
	environ := a.environ()
	include := o.vars
	if len(include) == 0 {
		v, _ := envvars.Lookup(environ, envVarsVar)
		include = envvars.ParseList(v)
	}
	if len(include) == 0 {
		include = defaults
	}
	exclude := o.exclude
	if len(exclude) == 0 {
		v, _ := envvars.Lookup(environ, envExcludeVar)
		exclude = envvars.ParseList(v)
	}
	return envvars.NewMatcher(include, exclude)
}

// envStatus says how a variable's value relates to the hash files.
type envStatus int

const (
	envNew       envStatus = iota // not in any hash file
	envBare                       // in a hash file only as a bare hash
	envPresent                    // already in a hash file with its length
	envShort                      // too short to be a safe secret
	envMultiline                  // spans several lines, which can't be matched
)

func (s envStatus) String() string {
	switch s {
	case envNew:
		return "new"
	case envBare:
		return "bare hash, add will upgrade it"
	case envPresent:
		return "in hash file"
	case envShort:
		return "too short, skipped"
	case envMultiline:
		return "multi-line, skipped"
	}
	return "unknown"
}

// envVar is a variable together with what is known about its value.
type envVar struct {
	envvars.Var
	chars  int // length in characters
	status envStatus
}

// classify works out the status of v. It never reveals the value.
func classify(v envvars.Var, set *hashes.Set) envVar {
	ev := envVar{Var: v, chars: utf8.RuneCountInString(v.Value)}
	sum := hashes.Hash([]byte(v.Value))
	switch {
	case strings.ContainsAny(v.Value, "\r\n"):
		ev.status = envMultiline
	case ev.chars < minSecretLen:
		ev.status = envShort
	case set.ContainsTagged(sum):
		ev.status = envPresent
	case set.Legacy(sum):
		ev.status = envBare
	}
	return ev
}

// ---------------------------------------------------------------------------
// --env: use environment variables while filtering

// addEnvSecrets adds the values of the variables chosen by the narrow patterns
// to set, in memory only.
func (a *app) addEnvSecrets(set *hashes.Set) error {
	m, err := a.envMatcher(a.filter.envOpts, envvars.Narrow)
	if err != nil {
		return err
	}
	var used []string
	for _, v := range m.Select(a.environ()) {
		switch ev := classify(v, hashes.NewSet()); ev.status {
		case envShort, envMultiline:
			if a.filter.verbose {
				_, _ = fmt.Fprintf(a.stderr, "password-cleaner: ignoring $%s: %s\n", v.Name, ev.status)
			}
		default:
			set.Add(hashes.New(v.Value))
			used = append(used, v.Name)
		}
	}
	if a.filter.verbose {
		_, _ = fmt.Fprintf(a.stderr, "password-cleaner: using %d environment variable(s)", len(used))
		if len(used) > 0 {
			_, _ = fmt.Fprintf(a.stderr, ": %s", strings.Join(used, ", "))
		}
		_, _ = fmt.Fprintln(a.stderr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// env list / env add

type envListFlags struct {
	envOpts
	hashFiles []string
	narrow    bool
}

type envAddFlags struct {
	envOpts
	hashFiles []string
	yes       bool
	dryRun    bool
	verbose   bool
}

const envLong = `Find secrets among your environment variables.

A variable counts as a secret if its name matches a pattern. The patterns for
these commands are broad (any name containing TOKEN, SECRET, PASSWORD, PASSWD,
PASS, KEY, CREDENTIAL, CRED, AUTH, PRIVATE, API or DSN, or ending in _PAT)
because you confirm each variable before it is added. Matching ignores case.
Use --env-var and --env-exclude, or $` + envVarsVar + ` and $` + envExcludeVar + `, to change them.

Only exported variables are visible. Values are never printed.`

func (a *app) envCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "List or add secrets held in environment variables",
		Long:  envLong,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(a.envListCmd(), a.envAddCmd())
	return cmd
}

func (a *app) envListCmd() *cobra.Command {
	f := &a.envList
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show variables that look like secrets and whether they are in the hash file",
		Long: "Show the environment variables whose names match the patterns, with the length of\n" +
			"each value and whether it is already in the hash file. Values are never printed.\n\n" + envLong,
		Args: cobra.NoArgs,
		RunE: a.runEnvList,
	}
	fl := cmd.Flags()
	f.register(fl)
	fl.StringArrayVarP(&f.hashFiles, "hash-file", "f", nil, "hash file to compare against; repeat for several")
	fl.BoolVar(&f.narrow, "narrow", false, "use the narrower patterns that --env uses when filtering")
	return cmd
}

func (a *app) envAddCmd() *cobra.Command {
	f := &a.envAdd
	cmd := &cobra.Command{
		Use:   "add [NAME...]",
		Short: "Add environment variable values to the hash file, asking first",
		Long: "Add the values of environment variables to the hash file, asking about each one.\n" +
			"With no NAME it offers every variable whose name matches the patterns; with names\n" +
			"it offers exactly those variables, whatever they are called.\n\n" +
			"Variables whose value is already in any of the hash files are skipped without\n" +
			"asking. Variables stored only as a bare hash are upgraded to include the length,\n" +
			"also without asking. Each new line is commented with the variable name and date.\n" +
			"Anything new is written to the first hash file, once all questions are answered.\n\n" +
			"At each question: y adds it, n (the default) skips it, a adds it and everything\n" +
			"after it, q stops asking (earlier yeses are still added).\n\n" + envLong,
		Example: "  password-cleaner env add\n" +
			"  password-cleaner env add GITHUB_TOKEN OPENAI_KEY\n" +
			"  password-cleaner env add --yes --env-var 'MYCO_*'",
		RunE: a.runEnvAdd,
	}
	fl := cmd.Flags()
	f.register(fl)
	fl.StringArrayVarP(&f.hashFiles, "hash-file", "f", nil,
		"hash file; repeat for several (new hashes go to the first, all are checked for duplicates)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "add everything new without asking")
	fl.BoolVarP(&f.dryRun, "dry-run", "n", false, "show what would be added without asking or writing")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "say why each skipped variable was skipped")
	return cmd
}

// loadEnvSet reads every hash file that exists. Files that do not exist are
// not an error here: the first one is where new hashes will go.
func (a *app) loadEnvSet(files []string) (set *hashes.Set, paths []string, err error) {
	paths, _, err = hashes.Resolve(files)
	if err != nil {
		return nil, nil, err
	}
	set = hashes.NewSet()
	for _, p := range paths {
		if _, err := set.LoadFile(p, func(msg string) { a.warnf("%s", msg) }); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
	}
	return set, paths, nil
}

func (a *app) runEnvList(*cobra.Command, []string) error {
	f := &a.envList
	set, _, err := a.loadEnvSet(f.hashFiles)
	if err != nil {
		return err
	}
	defaults := envvars.Broad
	if f.narrow {
		defaults = envvars.Narrow
	}
	m, err := a.envMatcher(f.envOpts, defaults)
	if err != nil {
		return err
	}
	vars := m.Select(a.environ())
	if len(vars) == 0 {
		_, _ = fmt.Fprintln(a.stderr, "no environment variables match the patterns")
		return nil
	}
	w := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tLENGTH\tSTATUS")
	for _, v := range vars {
		ev := classify(v, set)
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\n", ev.Name, ev.chars, ev.status)
	}
	return w.Flush()
}

// envGroup is one distinct secret value and the variables that hold it.
type envGroup struct {
	names []string
	value string
	chars int
	bare  bool // already in a hash file, but without its length
}

func (g *envGroup) describe() string {
	if len(g.names) == 1 {
		return fmt.Sprintf("%s (%d characters)", g.names[0], g.chars)
	}
	return fmt.Sprintf("%s (same value, %d characters)", joinNames(g.names), g.chars)
}

// joinNames writes ["A" "B" "C"] as "A, B and C".
func joinNames(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func (a *app) runEnvAdd(_ *cobra.Command, names []string) error {
	f := &a.envAdd
	set, paths, err := a.loadEnvSet(f.hashFiles)
	if err != nil {
		return err
	}
	target := paths[0]

	vars, err := a.envCandidates(names)
	if err != nil {
		return err
	}

	// Sort the variables out: skip, upgrade without asking, or ask.
	skipped := map[envStatus][]string{}
	byValue := map[string]*envGroup{}
	var toAsk, toUpgrade []*envGroup
	for _, v := range vars {
		ev := classify(v, set)
		switch ev.status {
		case envPresent, envShort, envMultiline:
			skipped[ev.status] = append(skipped[ev.status], ev.Name)
			continue
		}
		g := byValue[v.Value]
		if g == nil {
			g = &envGroup{value: v.Value, chars: ev.chars, bare: ev.status == envBare}
			byValue[v.Value] = g
			if g.bare {
				toUpgrade = append(toUpgrade, g)
			} else {
				toAsk = append(toAsk, g)
			}
		}
		g.names = append(g.names, ev.Name)
	}
	if f.verbose {
		for _, st := range []envStatus{envPresent, envShort, envMultiline} {
			for _, n := range skipped[st] {
				_, _ = fmt.Fprintf(a.stderr, "password-cleaner: skipped %s: %s\n", n, st)
			}
		}
	}

	if f.dryRun {
		for _, g := range toUpgrade {
			_, _ = fmt.Fprintf(a.stdout, "would upgrade %s\n", g.describe())
		}
		for _, g := range toAsk {
			_, _ = fmt.Fprintf(a.stdout, "would ask to add %s\n", g.describe())
		}
		_, _ = fmt.Fprintln(a.stdout, a.envSummary(skipped, 0, 0, 0, "", true))
		return nil
	}

	chosen := toAsk
	if len(toAsk) > 0 && !f.yes {
		if !a.isTTY(a.stdin) {
			return errors.New("cannot ask for confirmation without a terminal; use --yes to add without asking")
		}
		if chosen, err = a.confirm(toAsk); err != nil {
			return err
		}
	}

	var entries []hashes.Entry
	for _, g := range append(slices.Clone(toUpgrade), chosen...) {
		e := hashes.New(g.value)
		e.Comment = a.stamp(joinNames(g.names))
		entries = append(entries, e)
	}
	var res hashes.AppendResult
	if len(entries) > 0 {
		if res, err = hashes.Append(target, entries, false); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(a.stdout, a.envSummary(skipped, res.Added, res.Upgraded, len(toAsk)-len(chosen), target, false))
	return err
}

// envCandidates returns the variables to consider: those named, or else those
// whose names match the broad patterns.
func (a *app) envCandidates(names []string) ([]envvars.Var, error) {
	environ := a.environ()
	if len(names) == 0 {
		m, err := a.envMatcher(a.envAdd.envOpts, envvars.Broad)
		if err != nil {
			return nil, err
		}
		return m.Select(environ), nil
	}
	var vars []envvars.Var
	for _, n := range names {
		v, ok := envvars.Lookup(environ, n)
		if !ok || v == "" {
			return nil, fmt.Errorf("$%s is not set or is empty (only exported variables are visible)", n)
		}
		vars = append(vars, envvars.Var{Name: n, Value: v})
	}
	return vars, nil
}

// confirm asks about each group in turn and returns those the user accepted.
// Nothing is written here, so quitting part-way loses nothing already saved.
func (a *app) confirm(groups []*envGroup) ([]*envGroup, error) {
	in := bufio.NewReader(a.stdin)
	var chosen []*envGroup
	for i, g := range groups {
		answer, err := a.ask(in, fmt.Sprintf("Add %s? [y/N/a/q] ", g.describe()))
		if err != nil {
			return nil, err
		}
		switch answer {
		case "y":
			chosen = append(chosen, g)
		case "a":
			return append(chosen, groups[i:]...), nil
		case "q":
			return chosen, nil
		}
	}
	return chosen, nil
}

// ask prints question on stderr and returns "y", "n", "a" or "q". End of input
// counts as "q".
func (a *app) ask(in *bufio.Reader, question string) (string, error) {
	for {
		_, _ = fmt.Fprint(a.stderr, question)
		line, err := in.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		if err != nil && answer == "" {
			if errors.Is(err, io.EOF) {
				_, _ = fmt.Fprintln(a.stderr)
				return "q", nil
			}
			return "", err
		}
		switch answer {
		case "y", "yes":
			return "y", nil
		case "", "n", "no":
			return "n", nil
		case "a", "all":
			return "a", nil
		case "q", "quit":
			return "q", nil
		}
		_, _ = fmt.Fprintln(a.stderr, "Please answer y, n, a or q.")
		if err != nil {
			return "q", nil
		}
	}
}

// envSummary describes what happened, for example
// "added 2 hash(es), upgraded 1 to include the length, 3 already in the hash file; hash file: PATH".
func (a *app) envSummary(skipped map[envStatus][]string, added, upgraded, declined int, target string, dryRun bool) string {
	var parts []string
	if added > 0 {
		parts = append(parts, fmt.Sprintf("added %d hash(es)", added))
	}
	if upgraded > 0 {
		parts = append(parts, fmt.Sprintf("upgraded %d to include the length", upgraded))
	}
	if declined > 0 {
		parts = append(parts, fmt.Sprintf("%d declined", declined))
	}
	if n := len(skipped[envPresent]); n > 0 {
		parts = append(parts, fmt.Sprintf("%d already in the hash file", n))
	}
	if n := len(skipped[envShort]) + len(skipped[envMultiline]); n > 0 {
		parts = append(parts, fmt.Sprintf("%d too short or multi-line", n))
	}
	msg := strings.Join(parts, ", ")
	switch {
	case dryRun && msg != "":
		return "dry run, nothing written: " + msg
	case dryRun:
		return "dry run, nothing to add"
	case added == 0 && upgraded == 0 && msg == "":
		return "nothing to add"
	case added == 0 && upgraded == 0 && declined == 0:
		return "nothing to add: " + msg
	case added == 0 && upgraded == 0:
		return "nothing added: " + msg
	}
	return msg + "; hash file: " + target
}

func (a *app) environ() []string {
	if a.environFn != nil {
		return a.environFn()
	}
	return os.Environ()
}
