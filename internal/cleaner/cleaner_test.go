package cleaner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/jondoveston/password-cleaner/internal/hashes"
)

func tagged(secrets ...string) *hashes.Set {
	s := hashes.NewSet()
	for _, sec := range secrets {
		s.Add(hashes.New(sec))
	}
	return s
}

func bare(secrets ...string) *hashes.Set {
	s := hashes.NewSet()
	for _, sec := range secrets {
		e := hashes.New(sec)
		e.Length = 0
		s.Add(e)
	}
	return s
}

func TestFind(t *testing.T) {
	tests := []struct {
		name   string
		set    *hashes.Set
		minLen int
		line   string
		want   []Span
	}{
		{"tagged in the middle", tagged("hunter22"), 8, "my pw is hunter22, ok", []Span{{9, 17}}},
		{"tagged whole line", tagged("hunter22"), 8, "hunter22", []Span{{0, 8}}},
		{"tagged twice", tagged("hunter22"), 8, "hunter22 and hunter22", []Span{{0, 8}, {13, 21}}},
		{"tagged absent", tagged("hunter22"), 8, "nothing to see", nil},
		{"line shorter than secret", tagged("hunter22"), 8, "hunter", nil},
		{"empty line", tagged("hunter22"), 8, "", nil},
		{"short tagged secret ignores min length", tagged("1234"), 8, "pin 1234 here", []Span{{4, 8}}},
		{"two lengths", tagged("abcd", "longer secret"), 8, "x abcd y longer secret", []Span{{2, 6}, {9, 22}}},
		{"bare found", bare("hunter22"), 8, "pw hunter22!", []Span{{3, 11}}},
		{"bare below min length is not found", bare("abcd"), 8, "xx abcd xx", nil},
		{"bare at min length", bare("abcdefgh"), 8, "xabcdefghx", []Span{{1, 9}}},
		{"bare with lower min length", bare("abcd"), 4, "xx abcd xx", []Span{{3, 7}}},
		{"bare and tagged together", func() *hashes.Set {
			s := tagged("1234")
			s.Add(hashes.Entry{Sum: hashes.Hash([]byte("hunter22"))})
			return s
		}(), 8, "1234 hunter22", []Span{{0, 4}, {5, 13}}},
		{"utf-8 secret", tagged("pässwörd"), 8, "x pässwörd y", []Span{{2, 12}}},
		{"empty set", hashes.NewSet(), 8, "anything", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Find([]byte(tc.line), tc.set, tc.minLen, false)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFindFirstOnly(t *testing.T) {
	got := Find([]byte("hunter22 hunter22"), tagged("hunter22"), 8, true)
	if !slices.Equal(got, []Span{{0, 8}}) {
		t.Errorf("got %v", got)
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		spans []Span
		want  string
	}{
		{"none", "hello", nil, "hello"},
		{"one", "pw is hunter22!", []Span{{6, 14}}, "pw is <X>!"},
		{"two", "a b a", []Span{{0, 1}, {4, 5}}, "<X> b <X>"},
		{"overlapping", "abcdef", []Span{{0, 4}, {2, 6}}, "<X>"},
		{"touching", "abcdef", []Span{{0, 3}, {3, 6}}, "<X>"},
		{"nested", "abcdef", []Span{{0, 6}, {2, 4}}, "<X>"},
		{"whole line", "abc", []Span{{0, 3}}, "<X>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(Replace([]byte(tc.line), tc.spans, "<X>")); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func runFilter(t *testing.T, input string, opts Options) (out, rej string, stats Stats) {
	t.Helper()
	var o, r bytes.Buffer
	stats, err := Filter(strings.NewReader(input), &o, &r, opts)
	if err != nil {
		t.Fatal(err)
	}
	return o.String(), r.String(), stats
}

func TestFilterModes(t *testing.T) {
	set := tagged("hunter22")
	input := "clean one\nmy hunter22 pw\nclean two\n"

	t.Run("drop", func(t *testing.T) {
		out, rej, stats := runFilter(t, input, Options{Set: set, MinLength: 8, Mode: Drop})
		if out != "clean one\nclean two\n" || rej != "" {
			t.Errorf("out=%q rej=%q", out, rej)
		}
		if stats != (Stats{Lines: 3, Matched: 1}) {
			t.Errorf("stats = %+v", stats)
		}
	})
	t.Run("redact", func(t *testing.T) {
		out, rej, _ := runFilter(t, input, Options{Set: set, MinLength: 8, Mode: Redact, Replacement: "[R]"})
		if out != "clean one\nmy [R] pw\nclean two\n" || rej != "" {
			t.Errorf("out=%q rej=%q", out, rej)
		}
	})
	t.Run("stderr", func(t *testing.T) {
		out, rej, _ := runFilter(t, input, Options{Set: set, MinLength: 8, Mode: Stderr})
		if out != "clean one\nclean two\n" || rej != "my hunter22 pw\n" {
			t.Errorf("out=%q rej=%q", out, rej)
		}
	})
	t.Run("check", func(t *testing.T) {
		var lines []int
		out, rej, stats := runFilter(t, input, Options{
			Set: set, MinLength: 8, Check: true, OnMatch: func(n int) { lines = append(lines, n) },
		})
		if out != "" || rej != "" || !slices.Equal(lines, []int{2}) || stats.Matched != 1 {
			t.Errorf("out=%q rej=%q lines=%v stats=%+v", out, rej, lines, stats)
		}
	})
}

func TestFilterRedactsEveryOccurrence(t *testing.T) {
	out, _, _ := runFilter(t, "hunter22 and hunter22\n",
		Options{Set: tagged("hunter22"), MinLength: 8, Mode: Redact, Replacement: "*"})
	if out != "* and *\n" {
		t.Errorf("got %q", out)
	}
}

func TestFilterKeepsLineEndings(t *testing.T) {
	set := tagged("hunter22")
	opts := Options{Set: set, MinLength: 8, Mode: Drop}

	out, _, _ := runFilter(t, "a\r\nhunter22\r\nb\r\n", opts)
	if out != "a\r\nb\r\n" {
		t.Errorf("CRLF: %q", out)
	}
	out, _, _ = runFilter(t, "a\nb", opts)
	if out != "a\nb" {
		t.Errorf("no final newline: %q", out)
	}
	out, _, _ = runFilter(t, "a\nhunter22", opts)
	if out != "a\n" {
		t.Errorf("dropped last line: %q", out)
	}
	out, _, _ = runFilter(t, "a\n\n\nb\n", opts)
	if out != "a\n\n\nb\n" {
		t.Errorf("blank lines: %q", out)
	}
	opts.Mode = Redact
	opts.Replacement = "X"
	out, _, _ = runFilter(t, "pw hunter22\r\n", opts)
	if out != "pw X\r\n" {
		t.Errorf("redact CRLF: %q", out)
	}
	opts.Mode = Stderr
	_, rej, _ := runFilter(t, "pw hunter22", opts)
	if rej != "pw hunter22\n" {
		t.Errorf("stderr without newline: %q", rej)
	}
}

func TestFilterLongLines(t *testing.T) {
	long := strings.Repeat("x", 200_000)
	input := long + "\n" + long + "hunter22" + long + "\n" + long + "\n"
	out, _, stats := runFilter(t, input, Options{Set: tagged("hunter22"), MinLength: 8, Mode: Drop})
	if out != long+"\n"+long+"\n" || stats.Lines != 3 || stats.Matched != 1 {
		t.Errorf("len(out)=%d stats=%+v", len(out), stats)
	}
}

func TestFilterEmptySetPassesThrough(t *testing.T) {
	in := "a\nb\r\nc"
	out, _, stats := runFilter(t, in, Options{Set: hashes.NewSet(), MinLength: 8})
	if out != in || stats.Matched != 0 {
		t.Errorf("out=%q stats=%+v", out, stats)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestFilterReportsWriteErrors(t *testing.T) {
	_, err := Filter(strings.NewReader("hello\n"), failWriter{}, io.Discard,
		Options{Set: tagged("hunter22"), MinLength: 8})
	if err == nil {
		t.Error("expected an error")
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestFilterReportsReadErrors(t *testing.T) {
	_, err := Filter(failReader{}, io.Discard, io.Discard, Options{Set: tagged("hunter22"), MinLength: 8})
	if err == nil {
		t.Error("expected an error")
	}
}

func benchLine() []byte {
	return []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 5))
}

func BenchmarkFindTagged(b *testing.B) {
	line := benchLine()
	set := tagged("hunter22", "correct horse battery staple")
	b.ResetTimer()
	for range b.N {
		Find(line, set, 8, true)
	}
}

func BenchmarkFindBare(b *testing.B) {
	line := benchLine()
	set := bare("hunter22", "correct horse battery staple")
	b.ResetTimer()
	for range b.N {
		Find(line, set, 8, true)
	}
}

func ExampleFind() {
	set := tagged("hunter22")
	fmt.Println(Find([]byte("my password is hunter22"), set, 8, false))
	// Output: [{15 23}]
}
