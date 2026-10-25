// Package cleaner finds secrets in text and removes them.
package cleaner

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/jondoveston/password-cleaner/internal/hashes"
)

// Mode says what to do with a line that contains a secret.
type Mode int

const (
	// Drop removes the line from the output.
	Drop Mode = iota
	// Redact keeps the line but replaces each secret in it.
	Redact
	// Stderr writes the line to the rejected writer instead of the output.
	// The secret is therefore visible wherever that goes.
	Stderr
)

// Span is the half-open byte range [Start, End) of a secret within a line.
type Span struct{ Start, End int }

// Find returns the spans of line that hash to something in set, in order of
// start. If firstOnly is set it stops at the first one.
//
// Only substrings of the lengths recorded in set are hashed. Bare hashes carry
// no length, so if the set holds any, every substring of at least minLen bytes
// is hashed as well.
func Find(line []byte, set *hashes.Set, minLen int, firstOnly bool) []Span {
	lengths := set.Lengths()
	legacy := set.HasLegacy()
	if len(lengths) == 0 && !legacy {
		return nil
	}

	var spans []Span
	hit := func(start, n int) bool {
		sum := hashes.Hash(line[start : start+n])
		return set.Tagged(n, sum) || (legacy && n >= minLen && set.Legacy(sum))
	}

	for start := range len(line) {
		maxLen := len(line) - start
		if legacy {
			for n := 1; n <= maxLen; n++ {
				if n < minLen && !set.HasLength(n) {
					continue
				}
				if hit(start, n) {
					spans = append(spans, Span{start, start + n})
					if firstOnly {
						return spans
					}
				}
			}
			continue
		}
		for _, n := range lengths {
			if n > maxLen {
				break
			}
			if hit(start, n) {
				spans = append(spans, Span{start, start + n})
				if firstOnly {
					return spans
				}
			}
		}
	}
	return spans
}

// Replace returns line with every span replaced by replacement. Overlapping
// and touching spans are replaced once, together. spans must be ordered by
// start, as Find returns them.
func Replace(line []byte, spans []Span, replacement string) []byte {
	if len(spans) == 0 {
		return line
	}
	out := make([]byte, 0, len(line))
	pos := 0
	cur := spans[0]
	flush := func() {
		out = append(out, line[pos:cur.Start]...)
		out = append(out, replacement...)
		pos = cur.End
	}
	for _, s := range spans[1:] {
		if s.Start <= cur.End {
			cur.End = max(cur.End, s.End)
			continue
		}
		flush()
		cur = s
	}
	flush()
	return append(out, line[pos:]...)
}

// Options controls Filter.
type Options struct {
	Set *hashes.Set
	// MinLength is the shortest substring tried for bare hashes.
	MinLength int
	Mode      Mode
	// Replacement is what Redact puts in place of a secret.
	Replacement string
	// Check suppresses all output: lines are only counted, and OnMatch is told
	// about the ones that match. Mode is ignored.
	Check bool
	// OnMatch, if set, is called with the 1-based number of each matching line.
	OnMatch func(line int)
}

// Stats summarises a Filter run.
type Stats struct {
	Lines   int // lines read
	Matched int // lines that contained a secret
}

// Filter copies lines from in to out, handling those that contain a secret as
// opts.Mode says. Lines of any length are supported, and each line keeps its
// own ending (LF, CRLF, or none on the last line).
func Filter(in io.Reader, out, rejected io.Writer, opts Options) (Stats, error) {
	var stats Stats
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	firstOnly := opts.Check || opts.Mode != Redact

	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			stats.Lines++
			body, ending := splitEnding(line)
			spans := Find(body, opts.Set, opts.MinLength, firstOnly)
			if err := emit(w, rejected, body, ending, spans, opts); err != nil {
				_ = w.Flush()
				return stats, err
			}
			if len(spans) > 0 {
				stats.Matched++
				if opts.OnMatch != nil {
					opts.OnMatch(stats.Lines)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			_ = w.Flush()
			return stats, readErr
		}
	}
	return stats, w.Flush()
}

func emit(w *bufio.Writer, rejected io.Writer, body, ending []byte, spans []Span, opts Options) error {
	if opts.Check {
		return nil
	}
	if len(spans) == 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
		_, err := w.Write(ending)
		return err
	}
	switch opts.Mode {
	case Redact:
		if _, err := w.Write(Replace(body, spans, opts.Replacement)); err != nil {
			return err
		}
		_, err := w.Write(ending)
		return err
	case Stderr:
		if len(ending) == 0 {
			ending = []byte("\n")
		}
		if _, err := rejected.Write(append(append([]byte(nil), body...), ending...)); err != nil {
			return err
		}
	case Drop:
	}
	return nil
}

// splitEnding separates a line from its terminator.
func splitEnding(line []byte) (body, ending []byte) {
	switch {
	case bytes.HasSuffix(line, []byte("\r\n")):
		return line[:len(line)-2], line[len(line)-2:]
	case bytes.HasSuffix(line, []byte("\n")):
		return line[:len(line)-1], line[len(line)-1:]
	}
	return line, nil
}
