// Package envvars finds secrets among the environment variables.
//
// A variable is taken to hold a secret if its name matches a glob pattern.
// Names are matched case-insensitively with path.Match syntax ("*" matches any
// run of characters, "?" one character).
package envvars

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// ownPrefix starts the names of this program's own settings, which are never
// secrets.
const ownPrefix = "PASSWORD_CLEANER_"

// Broad matches many names, including some that are not secrets. It is for
// commands that ask before using each variable.
var Broad = []string{
	"*TOKEN*", "*SECRET*", "*PASSWORD*", "*PASSWD*", "*PASS*", "*KEY*",
	"*CREDENTIAL*", "*CRED*", "*AUTH*", "*PRIVATE*", "*API*", "*DSN*", "*_PAT",
}

// Narrow matches only names that are very likely secrets. It is for filtering,
// where nothing asks first and a false match costs a good line of output.
var Narrow = []string{
	"*TOKEN*", "*SECRET*", "*PASSWORD*", "*PASSWD*", "*_KEY", "*_API_KEY*",
	"*PRIVATE_KEY*", "*CREDENTIAL*",
}

// Var is one environment variable.
type Var struct {
	Name, Value string
}

// Matcher selects variables by name.
type Matcher struct {
	include, exclude []string
}

// NewMatcher returns a Matcher for names that match any include pattern and
// no exclude pattern.
func NewMatcher(include, exclude []string) (*Matcher, error) {
	inc, err := normalise(include)
	if err != nil {
		return nil, err
	}
	exc, err := normalise(exclude)
	if err != nil {
		return nil, err
	}
	return &Matcher{include: inc, exclude: exc}, nil
}

func normalise(patterns []string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Match reports whether name is selected.
func (m *Matcher) Match(name string) bool {
	name = strings.ToUpper(name)
	return matchAny(m.include, name) && !matchAny(m.exclude, name)
}

func matchAny(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		ok, _ := path.Match(p, name)
		return ok
	})
}

// ParseList splits a comma-separated list of patterns.
func ParseList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsOwn reports whether name is one of this program's own settings.
func IsOwn(name string) bool {
	return strings.HasPrefix(strings.ToUpper(name), ownPrefix)
}

// Lookup returns the value of the variable called name in environ (the
// "NAME=value" form of os.Environ). Like the OS, the last entry wins.
func Lookup(environ []string, name string) (string, bool) {
	for _, kv := range slices.Backward(environ) {
		if value, ok := strings.CutPrefix(kv, name+"="); ok {
			return value, true
		}
	}
	return "", false
}

// Parse turns environ into variables sorted by name.
func Parse(environ []string) []Var {
	byName := map[string]string{}
	for _, kv := range environ {
		if name, value, ok := strings.Cut(kv, "="); ok && name != "" {
			byName[name] = value
		}
	}
	vars := make([]Var, 0, len(byName))
	for name, value := range byName {
		vars = append(vars, Var{name, value})
	}
	slices.SortFunc(vars, func(a, b Var) int { return strings.Compare(a.Name, b.Name) })
	return vars
}

// Select returns the variables in environ whose names match, sorted by name.
// Variables with empty values and this program's own settings are left out.
func (m *Matcher) Select(environ []string) []Var {
	var out []Var
	for _, v := range Parse(environ) {
		if v.Value != "" && !IsOwn(v.Name) && m.Match(v.Name) {
			out = append(out, v)
		}
	}
	return out
}
