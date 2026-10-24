// Package probe reads a file's bytes (never executes it) and collects the strings that
// identify which runtime it carries and which Brotli decoder code was compiled into it.
package probe

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Evidence is everything lotstamp learned from one file.
type Evidence struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Format string `json:"format"` // elf, macho, pe, other

	Bun      []string `json:"bun,omitempty"`      // Bun/1.4.4
	Node     []string `json:"node,omitempty"`     // from nodejs.org .../node-vX.Y.Z-headers URLs
	Electron []string `json:"electron,omitempty"` // Electron/42.11.16
	Chrome   []string `json:"chrome,omitempty"`   // Chrome/148.0.7778.x (only kept when Electron is present)

	// DecoderNames are the distinct Brotli _ERROR_FORMAT_* names found (from the advisory's
	// list plus the fix marker). FixMarker says whether the fix's new name is among them.
	DecoderNames int  `json:"decoder_names"`
	FixMarker    bool `json:"fix_marker"`

	Needed []string `json:"needed,omitempty"` // dynamic libraries it links (ELF DT_NEEDED, Mach-O load commands, PE imports)
	RPath  []string `json:"rpath,omitempty"`
	Packed string   `json:"packed,omitempty"` // "appimage": the payload is compressed, strings can't be read

	// LinkedDecoder is set when the file links a shared Brotli decoder library. Its own
	// _ERROR_FORMAT_ strings are then Node's zlib.constants (compiled from build-time headers),
	// not decoder code, so they are not used as evidence; the library is judged instead.
	LinkedDecoder string `json:"linked_decoder,omitempty"`
}

var (
	reBun      = regexp.MustCompile(`^Bun/(1\.[0-9]+\.[0-9]+)`)
	reBunV     = regexp.MustCompile(`^Bun v(1\.[0-9]+\.[0-9]+)`)
	reNode     = regexp.MustCompile(`/node-v([0-9]+\.[0-9]+\.[0-9]+)-headers`)
	reElectron = regexp.MustCompile(`^Electron/([0-9]+\.[0-9]+\.[0-9]+)`)
	reChrome   = regexp.MustCompile(`^Chrome/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	reErr      = regexp.MustCompile(`^_ERROR_FORMAT_[A-Z0-9_]+`)
)

type anchor struct {
	lit    []byte
	before int // how far back the token may start
	re     *regexp.Regexp
	into   string
}

var anchors = []anchor{
	{[]byte("Bun/1."), 0, reBun, "bun"},
	{[]byte("Bun v1."), 0, reBunV, "bun"},
	{[]byte("-headers"), 80, reNode, "node"},
	{[]byte("Electron/"), 0, reElectron, "electron"},
	{[]byte("Chrome/"), 0, reChrome, "chrome"},
	{[]byte("_ERROR_FORMAT_"), 0, reErr, "err"},
	// Brotli 1.0.x returns bare names ("EXUBERANT_NIBBLE") from BrotliDecoderErrorString;
	// 1.1.0 and later return "_ERROR_FORMAT_EXUBERANT_NIBBLE". The bare table is read as a
	// run of NUL-separated strings around its most distinctive entry.
	{[]byte("\x00EXUBERANT_META_NIBBLE\x00"), 0, nil, "bare"},
}

const chunk = 8 << 20
const overlap = 256

// Options for File.
type Options struct {
	DecoderNames []string // the decoder's known error names
	FixMarker    string
}

// File streams path and returns its evidence.
func File(path string, o Options) (*Evidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	ev := &Evidence{Path: path, Size: st.Size(), Format: "other"}
	known := map[string]bool{}
	for _, n := range o.DecoderNames {
		known[n] = true
	}
	counts := map[string]map[string]int{"bun": {}, "node": {}, "electron": {}, "chrome": {}}
	errs := map[string]bool{}

	buf := make([]byte, chunk+overlap)
	carry := 0
	var off int64
	for {
		n, rerr := io.ReadFull(f, buf[carry:])
		data := buf[:carry+n]
		if off == 0 {
			ev.Format = magic(data)
			if bytes.Contains(data[:min(len(data), 4096)], []byte("AI\x02")) && ev.Format == "elf" && isAppImage(data) {
				ev.Packed = "appimage"
			}
		}
		final := rerr != nil
		// Only tokens that start before limit are taken from this window; the overlap
		// region is rescanned with the next chunk so nothing is counted twice.
		limit := len(data)
		if !final {
			limit = len(data) - overlap
		}
		for _, a := range anchors {
			from := 0
			for {
				i := bytes.Index(data[from:], a.lit)
				if i < 0 {
					break
				}
				i += from
				from = i + 1
				start := i - a.before
				if start < 0 {
					start = 0
				}
				if i >= limit {
					break
				}
				if a.into == "bare" {
					lo, hi := max(0, i-1024), min(len(data), i+1024)
					for _, tok := range bytes.Split(data[lo:hi], []byte{0}) {
						name := "_ERROR_FORMAT_" + string(tok)
						if known[name] || name == o.FixMarker {
							errs[name] = true
						}
					}
					continue
				}
				end := min(len(data), i+120)
				win := data[start:end]
				m := a.re.FindSubmatch(win)
				if m == nil {
					continue
				}
				switch a.into {
				case "err":
					name := string(m[0])
					if known[name] || name == o.FixMarker {
						errs[name] = true
					}
				default:
					counts[a.into][string(m[1])]++
				}
			}
		}
		if final {
			break
		}
		copy(buf, data[len(data)-overlap:])
		carry = overlap
		off += int64(n)
	}
	ev.Bun = ranked(counts["bun"])
	ev.Node = ranked(counts["node"])
	ev.Electron = ranked(counts["electron"])
	if len(ev.Electron) > 0 {
		ev.Chrome = ranked(counts["chrome"])
	}
	for n := range errs {
		if n == o.FixMarker {
			ev.FixMarker = true
		}
		ev.DecoderNames++
	}
	linkInfo(path, ev)
	if lib := ev.NeedsBrotli(); lib != "" {
		ev.LinkedDecoder = lib
		ev.DecoderNames, ev.FixMarker = 0, false
	}
	return ev, nil
}

func ranked(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

func magic(b []byte) string {
	switch {
	case len(b) >= 4 && bytes.Equal(b[:4], []byte("\x7fELF")):
		return "elf"
	case len(b) >= 4 && (bytes.Equal(b[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) || bytes.Equal(b[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) || bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe})):
		return "macho"
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		return "pe"
	}
	return "other"
}

// AppImages are ELF runtimes with "AI\x02" at offset 8 and a squashfs payload.
func isAppImage(b []byte) bool { return len(b) > 11 && b[8] == 'A' && b[9] == 'I' && b[10] == 2 }

// Magic reports the executable format of a file from its first bytes.
func Magic(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, 16)
	n, _ := io.ReadFull(f, b)
	return magic(b[:n])
}

func linkInfo(path string, ev *Evidence) {
	switch ev.Format {
	case "elf":
		f, err := elf.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		ev.Needed, _ = f.ImportedLibraries()
		for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
			if v, err := f.DynString(tag); err == nil {
				for _, s := range v {
					ev.RPath = append(ev.RPath, strings.Split(s, ":")...)
				}
			}
		}
	case "macho":
		f, err := macho.Open(path)
		if err != nil {
			if ff, err2 := macho.OpenFat(path); err2 == nil {
				defer ff.Close()
				if len(ff.Arches) > 0 {
					ev.Needed, _ = ff.Arches[0].ImportedLibraries()
				}
			}
			return
		}
		defer f.Close()
		ev.Needed, _ = f.ImportedLibraries()
	case "pe":
		f, err := pe.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		ev.Needed, _ = f.ImportedLibraries()
	}
}

// HasDecoder reports whether the file carries a Brotli decoder's error table.
func (e *Evidence) HasDecoder(minNames int) bool { return e.DecoderNames >= minNames }

// NeedsBrotli returns the linked Brotli decoder library name, if any.
func (e *Evidence) NeedsBrotli() string {
	for _, n := range e.Needed {
		b := strings.ToLower(n)
		if i := strings.LastIndexAny(b, `/\`); i >= 0 {
			b = b[i+1:]
		}
		if strings.HasPrefix(b, "libbrotlidec") || strings.HasPrefix(b, "brotlidec") {
			return n
		}
	}
	return ""
}
