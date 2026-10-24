// Package advisory holds the data lotstamp checks against. Everything that is specific to one
// vulnerability lives in the embedded JSON, so the next decoder bug is a data change.
package advisory

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
)

//go:embed CVE-2026-111497.json
var raw []byte

type Advisory struct {
	ID            string   `json:"id"`
	Names         []string `json:"names"`
	Title         string   `json:"title"`
	Published     string   `json:"published"`
	DecoderNames  []string `json:"decoder_names"`
	MinDecoder    int      `json:"min_decoder_names"`
	FixMarker     string   `json:"fix_marker"`
	FixMarkerWhy  string   `json:"fix_marker_why"`
	UpstreamFixed []string `json:"upstream_fixed"`
	UpstreamFrom  string   `json:"upstream_affected_from"`
	Node          struct {
		Fixed  map[string]string `json:"fixed"`
		Advice string            `json:"advice"`
	} `json:"node"`
	Bun struct {
		Fixed string `json:"fixed"`
	} `json:"bun"`
	Electron struct {
		FixedChromiumMajor int    `json:"fixed_chromium_major"`
		Why                string `json:"why"`
	} `json:"electron"`
	PyPI    map[string]string `json:"pypi"`
	Distros map[string]Distro `json:"distros"`
	Links   []string          `json:"links"`
}

type Distro struct {
	Package    string            `json:"package"`
	Fixed      map[string]string `json:"fixed"`
	Unfixed    []string          `json:"unfixed"`
	Advisories map[string]string `json:"advisories"`
	Note       string            `json:"note"`
}

// Load returns the embedded advisory. It panics only if the embedded file is broken,
// which the tests catch.
func Load() *Advisory {
	var a Advisory
	if err := json.Unmarshal(raw, &a); err != nil {
		panic("advisory: embedded JSON: " + err.Error())
	}
	return &a
}

// Major returns the leading number of a dotted version ("24.19.0" -> 24), or -1.
func Major(v string) int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}

// Cmp compares dotted numeric versions ("1.4.10" > "1.4.4"). Non-numeric parts compare as 0.
func Cmp(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// NodeFixFor returns the fixed release on the same major line, or "" when that line gets none.
func (a *Advisory) NodeFixFor(version string) string {
	return a.Node.Fixed[strconv.Itoa(Major(version))]
}

// UpstreamFixFor returns the fixed Brotli release for an upstream Brotli version, choosing the
// patch release on the same minor line when there is one (1.1.0 -> 1.1.1), else the newest.
func (a *Advisory) UpstreamFixFor(v string) string {
	parts := strings.Split(v, ".")
	for _, f := range a.UpstreamFixed {
		fp := strings.Split(f, ".")
		if len(parts) >= 2 && len(fp) >= 2 && parts[0] == fp[0] && parts[1] == fp[1] {
			return f
		}
	}
	return a.UpstreamFixed[len(a.UpstreamFixed)-1]
}

// UpstreamFixed reports whether an upstream Brotli version is outside the affected range.
func (a *Advisory) UpstreamIsFixed(v string) bool {
	if Cmp(v, a.UpstreamFrom) < 0 {
		return true
	}
	return Cmp(v, a.UpstreamFixFor(v)) >= 0
}
