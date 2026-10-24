// Package scan probes discovered files in parallel, follows dynamic links to shared Brotli
// decoders (and libnode, which links them on distro builds), and produces findings.
package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/Blackman99/lotstamp/internal/advisory"
	"github.com/Blackman99/lotstamp/internal/discover"
	"github.com/Blackman99/lotstamp/internal/pkgdb"
	"github.com/Blackman99/lotstamp/internal/probe"
	"github.com/Blackman99/lotstamp/internal/verdict"
)

type Result struct {
	Findings []verdict.Finding `json:"findings"`
	Scanned  int               `json:"files_read"`
	Errors   []string          `json:"errors,omitempty"`
}

type item struct {
	sub verdict.Subject
	ev  *probe.Evidence
	err error
}

// Run probes every subject and judges it.
func Run(a *advisory.Advisory, subs []verdict.Subject, osr pkgdb.OS) Result {
	opts := probe.Options{DecoderNames: a.DecoderNames, FixMarker: a.FixMarker}
	items := probeAll(subs, opts)

	// Follow links: binary -> libnode -> libbrotlidec. Libraries become their own subjects.
	byPath := map[string]*item{}
	for i := range items {
		byPath[items[i].sub.Real] = &items[i]
	}
	type link struct{ user, chain, node string }
	users := map[string][]link{}
	var pending []verdict.Subject
	var walk func(it *item, chain, node string, depth int)
	seenLib := map[string]bool{}
	walk = func(it *item, chain, node string, depth int) {
		if it.ev == nil || depth > 3 {
			return
		}
		if len(it.ev.Node) > 0 {
			node = it.ev.Node[0]
		}
		for _, lib := range interestingLibs(it.ev) {
			p := resolve(lib, it.ev, it.sub.Real)
			if p == "" {
				continue
			}
			c := chain + " → " + filepath.Base(lib)
			users[p] = append(users[p], link{user: rootOf(chain), chain: c, node: node})
			if seenLib[p] {
				continue
			}
			seenLib[p] = true
			if _, ok := byPath[p]; ok {
				continue
			}
			sub := verdict.Subject{Path: p, Real: p, Origin: "runtime", Label: filepath.Base(p), SysLib: isBrotliLib(p)}
			if sub.SysLib {
				sub.Label = "Brotli decoder library " + filepath.Base(p)
			}
			if sub.SysLib {
				if pk, ok := pkgdb.DpkgOwner(p); ok {
					sub.Package = &pk
				}
			}
			ev, err := probe.File(p, opts)
			ni := &item{sub: sub, ev: ev, err: err}
			byPath[p] = ni
			pending = append(pending, sub)
			if ev != nil && len(ev.Node) > 0 {
				for k, l := range users[p] {
					if l.node == "" {
						users[p][k].node = ev.Node[0]
					}
				}
			}
			walk(ni, c, node, depth+1)
		}
	}
	for i := range items {
		walk(&items[i], items[i].sub.Real, "", 0)
	}
	for _, s := range pending {
		items = append(items, *byPath[s.Real])
	}

	var res Result
	for _, it := range items {
		if it.err != nil {
			res.Errors = append(res.Errors, it.sub.Path+": "+it.err.Error())
			continue
		}
		res.Scanned++
		sub := it.sub
		for _, l := range users[sub.Real] {
			u := byPath[l.user]
			desc := l.chain
			if u != nil {
				desc = u.sub.Path
				if l.node != "" {
					desc += " (Node " + l.node + ")"
				}
				desc += "  via " + strings.TrimPrefix(strings.TrimPrefix(l.chain, l.user), " → ")
				for _, m := range u.sub.MCP {
					if !has(sub.MCP, m) {
						sub.MCP = append(sub.MCP, m)
					}
				}
			}
			if !has(sub.UsedBy, desc) {
				sub.UsedBy = append(sub.UsedBy, desc)
			}
		}
		f := verdict.Judge(a, sub, it.ev, osr)
		if strings.HasPrefix(filepath.Base(sub.Real), "libnode") && f.Status == verdict.Absent {
			continue // libnode on distro builds: its decoder is the system library, reported there
		}
		res.Findings = append(res.Findings, f)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		ri, rj := verdict.Rank(res.Findings[i].Status), verdict.Rank(res.Findings[j].Status)
		if ri != rj {
			return ri < rj
		}
		return res.Findings[i].Path < res.Findings[j].Path
	})
	return res
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func rootOf(chain string) string {
	r, _, _ := strings.Cut(chain, " → ")
	return r
}

func probeAll(subs []verdict.Subject, opts probe.Options) []item {
	items := make([]item, len(subs))
	n := runtime.NumCPU()
	if n > 4 {
		n = 4 // big sequential reads; more workers only thrash the disk
	}
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				ev, err := probe.File(subs[i].Real, opts)
				items[i] = item{sub: subs[i], ev: ev, err: err}
			}
		}()
	}
	for i := range subs {
		ch <- i
	}
	close(ch)
	wg.Wait()
	return items
}

func isBrotliLib(p string) bool {
	b := strings.ToLower(filepath.Base(p))
	return strings.HasPrefix(b, "libbrotlidec") || strings.HasPrefix(b, "brotlidec")
}

func interestingLibs(ev *probe.Evidence) []string {
	var out []string
	for _, n := range ev.Needed {
		b := strings.ToLower(filepath.Base(filepath.ToSlash(n)))
		if strings.HasPrefix(b, "libbrotlidec") || strings.HasPrefix(b, "brotlidec") || strings.HasPrefix(b, "libnode") {
			out = append(out, n)
		}
	}
	return out
}

var defaultLibDirs = []string{
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	"/lib64", "/usr/lib64", "/lib", "/usr/lib", "/usr/local/lib", "/opt/homebrew/lib",
}

// resolve finds the file a dynamic library reference points at, like the loader would
// (rpath with $ORIGIN, LD_LIBRARY_PATH, ld.so.conf, default dirs). Returns "" if not found.
func resolve(lib string, ev *probe.Evidence, user string) string {
	origin := filepath.Dir(user)
	if strings.HasPrefix(lib, "@rpath/") || strings.HasPrefix(lib, "@loader_path/") || strings.HasPrefix(lib, "@executable_path/") {
		rest := lib[strings.IndexByte(lib, '/')+1:]
		for _, d := range []string{origin, filepath.Join(origin, "..", "lib"), filepath.Join(origin, "..", "Frameworks")} {
			if p := real(filepath.Join(d, rest)); p != "" {
				return p
			}
		}
		return ""
	}
	if filepath.IsAbs(lib) {
		return real(lib)
	}
	var dirs []string
	for _, r := range ev.RPath {
		r = strings.ReplaceAll(strings.ReplaceAll(r, "${ORIGIN}", origin), "$ORIGIN", origin)
		dirs = append(dirs, r)
	}
	dirs = append(dirs, filepath.SplitList(os.Getenv("LD_LIBRARY_PATH"))...)
	dirs = append(dirs, ldSoConf()...)
	dirs = append(dirs, defaultLibDirs...)
	dirs = append(dirs, origin) // Windows: DLLs next to the exe
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if p := real(filepath.Join(d, lib)); p != "" {
			return p
		}
	}
	return ""
}

func real(p string) string {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	if st, err := os.Stat(r); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return r
}

var ldOnce sync.Once
var ldDirs []string

func ldSoConf() []string {
	ldOnce.Do(func() {
		files, _ := filepath.Glob("/etc/ld.so.conf.d/*.conf")
		files = append([]string{"/etc/ld.so.conf"}, files...)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(b), "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "/") {
					ldDirs = append(ldDirs, l)
				}
			}
		}
	})
	return ldDirs
}

var _ = discover.MinBinary
