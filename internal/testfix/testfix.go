// Package testfix builds small synthetic binaries that carry the same byte patterns lotstamp
// reads in real runtimes. They are not executable; they only look like it to a reader.
package testfix

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Names are the 16 decoder error names every pre-fix Brotli carries.
var Names = []string{"EXUBERANT_NIBBLE", "RESERVED", "EXUBERANT_META_NIBBLE", "SIMPLE_HUFFMAN_ALPHABET",
	"SIMPLE_HUFFMAN_SAME", "CL_SPACE", "HUFFMAN_SPACE", "CONTEXT_MAP_REPEAT", "BLOCK_LENGTH_1",
	"BLOCK_LENGTH_2", "TRANSFORM", "DICTIONARY", "WINDOW_BITS", "PADDING_1", "PADDING_2", "DISTANCE"}

// Spec describes one fake binary.
type Spec struct {
	Fixed bool   // add BLOCK_SWITCH to the table
	Bare  bool   // Brotli 1.0.x style: names without the _ERROR_FORMAT_ prefix
	Table bool   // include a decoder table at all
	Extra string // other strings (version markers)
	Magic string // defaults to ELF
	Pad   int    // filler bytes before the strings
}

// Bytes renders a spec.
func Bytes(s Spec) []byte {
	var b bytes.Buffer
	if s.Magic == "" {
		s.Magic = "\x7fELF"
	}
	b.WriteString(s.Magic)
	b.Write(make([]byte, 60+s.Pad))
	b.WriteString(s.Extra)
	b.WriteByte(0)
	if s.Table {
		names := append([]string{}, Names...)
		if s.Fixed {
			names = append(names, "BLOCK_SWITCH")
		}
		for _, n := range names {
			if !s.Bare {
				n = "_ERROR_FORMAT_" + n
			}
			b.WriteString(n)
			b.WriteByte(0)
		}
	}
	b.Write(make([]byte, 64))
	return b.Bytes()
}

// Write puts a fake binary at dir/rel and returns its path.
func Write(t testing.TB, dir, rel string, s Spec) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, Bytes(s), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// File writes a plain file.
func File(t testing.TB, dir, rel, body string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.TrimLeft(body, "\n")), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// NodeHeaders is the string every official Node binary embeds.
func NodeHeaders(v string) string {
	return "https://nodejs.org/download/release/v" + v + "/node-v" + v + "-headers.tar.gz"
}
