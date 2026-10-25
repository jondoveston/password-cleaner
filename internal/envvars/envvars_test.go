package envvars

import (
	"slices"
	"testing"
)

func names(vars []Var) []string {
	var out []string
	for _, v := range vars {
		out = append(out, v.Name)
	}
	return out
}

func TestMatcher(t *testing.T) {
	broad, err := NewMatcher(Broad, nil)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := NewMatcher(Narrow, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		broad, narrow bool
	}{
		{"GITHUB_TOKEN", true, true},
		{"github_token", true, true},
		{"AWS_SECRET_ACCESS_KEY", true, true},
		{"DB_PASSWORD", true, true},
		{"MYSQL_PASSWD", true, true},
		{"OPENAI_KEY", true, true},
		{"STRIPE_API_KEY", true, true},
		{"SSH_PRIVATE_KEY", true, true},
		{"GOOGLE_CREDENTIALS", true, true},
		{"GITLAB_PAT", true, false},
		{"SENTRY_DSN", true, false},
		{"SSH_AUTH_SOCK", true, false},
		{"GPG_KEY_ID", true, false},
		{"KEYTIMEOUT", true, false},
		{"XKB_KEYMAP", true, false},
		{"MY_API", true, false},
		{"PATH", false, false},
		{"HOME", false, false},
		{"EDITOR", false, false},
	}
	for _, tc := range tests {
		if got := broad.Match(tc.name); got != tc.broad {
			t.Errorf("broad %s = %v, want %v", tc.name, got, tc.broad)
		}
		if got := narrow.Match(tc.name); got != tc.narrow {
			t.Errorf("narrow %s = %v, want %v", tc.name, got, tc.narrow)
		}
	}
}

func TestMatcherExclude(t *testing.T) {
	m, err := NewMatcher([]string{"*KEY*"}, []string{"*keymap*", " KEYTIMEOUT "})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"OPENAI_KEY": true, "XKB_KEYMAP": false, "KEYTIMEOUT": false} {
		if m.Match(name) != want {
			t.Errorf("%s = %v, want %v", name, !want, want)
		}
	}
}

func TestMatcherNothingIncluded(t *testing.T) {
	m, _ := NewMatcher(nil, nil)
	if m.Match("GITHUB_TOKEN") {
		t.Error("an empty include list should match nothing")
	}
}

func TestInvalidPattern(t *testing.T) {
	if _, err := NewMatcher([]string{"[oops"}, nil); err == nil {
		t.Error("expected an error for an include pattern")
	}
	if _, err := NewMatcher([]string{"*"}, []string{"[oops"}); err == nil {
		t.Error("expected an error for an exclude pattern")
	}
}

func TestSelect(t *testing.T) {
	m, _ := NewMatcher([]string{"*TOKEN*", "*KEY*"}, nil)
	environ := []string{
		"B_TOKEN=bbbbbbbb",
		"A_KEY=aaaaaaaa",
		"EMPTY_TOKEN=",
		"PASSWORD_CLEANER_ENV_VARS=*KEY*",
		"password_cleaner_key=x",
		"HOME=/home/me",
		"malformed",
		"=C:=C:\\",
	}
	got := names(m.Select(environ))
	if !slices.Equal(got, []string{"A_KEY", "B_TOKEN"}) {
		t.Errorf("got %v", got)
	}
}

func TestParseLastWins(t *testing.T) {
	vars := Parse([]string{"A=1", "B=2", "A=3"})
	if len(vars) != 2 || vars[0] != (Var{"A", "3"}) {
		t.Errorf("got %v", vars)
	}
}

func TestValueMayContainEquals(t *testing.T) {
	vars := Parse([]string{"X_TOKEN=abc=def=="})
	if len(vars) != 1 || vars[0].Value != "abc=def==" {
		t.Errorf("got %v", vars)
	}
}

func TestLookup(t *testing.T) {
	environ := []string{"A=1", "AB=2", "A=3"}
	if v, ok := Lookup(environ, "A"); !ok || v != "3" {
		t.Errorf("got %q %v", v, ok)
	}
	if v, ok := Lookup(environ, "AB"); !ok || v != "2" {
		t.Errorf("got %q %v", v, ok)
	}
	if _, ok := Lookup(environ, "C"); ok {
		t.Error("C should not be found")
	}
}

func TestParseList(t *testing.T) {
	if got := ParseList(" A* , ,B?,"); !slices.Equal(got, []string{"A*", "B?"}) {
		t.Errorf("got %v", got)
	}
	if got := ParseList(""); got != nil {
		t.Errorf("got %v", got)
	}
}
