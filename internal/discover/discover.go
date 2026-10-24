// Package discover finds the files that may carry a Brotli decoder: runtimes on PATH and in
// version managers, AI coding tools' native binaries, app bundles, Python Brotli modules,
// and the runtimes that MCP servers are launched with. It only stats and reads.
package discover

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Blackman99/lotstamp/internal/probe"
	"github.com/Blackman99/lotstamp/internal/verdict"
)

// MinBinary is the size below which an executable cannot hold a JS runtime.
const MinBinary = 8 << 20

type Set struct {
	byReal map[string]*verdict.Subject
	order  []string
	Notes  []string
}

func NewSet() *Set { return &Set{byReal: map[string]*verdict.Subject{}} }

func (s *Set) Subjects() []verdict.Subject {
	out := make([]verdict.Subject, 0, len(s.order))
	for _, r := range s.order {
		out = append(out, *s.byReal[r])
	}
	return out
}

// Add records a candidate, merging duplicates (same file reached two ways).
func (s *Set) Add(path, origin, via string) *verdict.Subject {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil
	}
	if abs, err := filepath.Abs(real); err == nil {
		real = abs
	}
	sub, ok := s.byReal[real]
	if !ok {
		sub = s.sameFile(real)
	}
	if sub != nil {
		if via != "" && !contains(sub.Via, via) {
			sub.Via = append(sub.Via, via)
		}
		if origin == "runtime" {
			sub.Origin = "runtime"
		}
		return sub
	}
	sub = &verdict.Subject{Path: real, Real: real, Origin: origin, Label: Label(real)}
	if b := strings.ToLower(filepath.Base(real)); strings.HasPrefix(b, "libbrotlidec") || strings.HasPrefix(b, "brotlidec") {
		sub.SysLib = true
		sub.Label = "Brotli decoder library " + filepath.Base(real)
	}
	if dist, ver := pyInfo(real); dist != "" {
		sub.PyDist, sub.PyVer, sub.Origin = dist, ver, "runtime"
		sub.Label = strings.TrimSpace("Python " + dist + " " + ver)
	}
	if via != "" {
		sub.Via = []string{via}
	}
	s.byReal[real] = sub
	s.order = append(s.order, real)
	return sub
}

// sameFile finds an already-added hard link of the same file (pnpm stores, npm copies).
func (s *Set) sameFile(p string) *verdict.Subject {
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	for _, o := range s.order {
		if ost, err := os.Stat(o); err == nil && ost.Size() == st.Size() && os.SameFile(st, ost) {
			return s.byReal[o]
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

var labels = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`claude[/\\]versions[/\\]([0-9][0-9.]*)`), "Claude Code $1"},
	{regexp.MustCompile(`claude-code-releases[/\\]([0-9][0-9.]*)`), "Claude Code $1"},
	{regexp.MustCompile(`@anthropic-ai[/\\]claude-code`), "Claude Code (npm)"},
	{regexp.MustCompile(`(?i)claude[ -]?desktop|Claude\.app|AnthropicClaude`), "Claude Desktop"},
	{regexp.MustCompile(`(?i)cursor-agent|cursor[/\\]agent|\.local[/\\]share[/\\]cursor-agent`), "Cursor agent CLI"},
	{regexp.MustCompile(`(?i)resources[/\\]app[/\\]resources[/\\]helpers[/\\]node`), "app helper node"},
	{regexp.MustCompile(`(?i)opencode`), "OpenCode"},
	{regexp.MustCompile(`(?i)@github[/\\]copilot|copilot`), "Copilot CLI"},
	{regexp.MustCompile(`(?i)windsurf|devin`), "Windsurf"},
	{regexp.MustCompile(`(?i)kiro`), "Kiro"},
	{regexp.MustCompile(`(?i)cursor`), "Cursor"},
	{regexp.MustCompile(`(?i)VSCode|Visual Studio Code|[/\\]code$|code-insiders`), "VS Code"},
	{regexp.MustCompile(`(?i)[/\\]bun@([0-9][0-9.]*)[/\\]`), "bun $1 (package)"},
	{regexp.MustCompile(`(?i)node-v([0-9][0-9.]*)-`), "node $1 tarball"},
}

// Label names a file for humans from its path.
func Label(p string) string {
	slash := filepath.ToSlash(p)
	for _, l := range labels {
		if m := l.re.FindStringSubmatchIndex(slash); m != nil {
			name := string(l.re.ExpandString(nil, l.name, slash, m))
			// a helper inside an app bundle: say which one (VS Code · vsce-sign)
			if i := strings.Index(slash, "/resources/"); i > 0 && !strings.Contains(slash, "/helpers/node") {
				name += " · " + filepath.Base(p)
			}
			return name
		}
	}
	return filepath.Base(p)
}

// Interesting reports whether a file is worth reading in full.
func Interesting(path string, info fs.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	if isRuntimeName(base) || strings.HasPrefix(base, "libbrotlidec") || strings.HasPrefix(base, "libnode.") ||
		base == "electron framework" || isPyBrotli(base) {
		return info.Size() > 0
	}
	if info.Size() < MinBinary {
		return false
	}
	if strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.") || strings.HasSuffix(base, ".dylib") ||
		strings.HasSuffix(base, ".pak") || strings.HasSuffix(base, ".asar") || strings.HasSuffix(base, ".dat") ||
		strings.HasSuffix(base, ".bin") || strings.HasSuffix(base, ".node") {
		return false
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(base, ".exe") {
		return false // DLLs other than libbrotlidec/libnode don't carry a JS runtime's decoder
	}
	return probe.Magic(path) != "other"
}

func isRuntimeName(b string) bool {
	switch strings.TrimSuffix(b, ".exe") {
	case "node", "bun", "bunx", "nodejs":
		return true
	}
	return false
}

func isPyBrotli(b string) bool {
	return (strings.HasPrefix(b, "_brotli") || strings.HasPrefix(b, "_brotlicffi")) &&
		(strings.HasSuffix(b, ".so") || strings.HasSuffix(b, ".pyd"))
}

// Walk adds every interesting file under root, up to depth levels down.
func (s *Set) Walk(root, origin, via string, depth int) {
	root = filepath.Clean(root)
	baseDepth := strings.Count(root, string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, string(filepath.Separator))-baseDepth >= depth {
				return filepath.SkipDir
			}
			switch d.Name() {
			case ".git", "proc", "__pycache__", "locales", "icons", "man", "doc", "include", "store", ".cache":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if Interesting(p, info) {
			s.Add(p, originFor(p, origin), via)
		}
		return nil
	})
}

func originFor(p, def string) string {
	if def != "" {
		return def
	}
	if isRuntimeName(strings.ToLower(filepath.Base(p))) && !strings.Contains(filepath.ToSlash(p), "/resources/") {
		return "runtime"
	}
	return "app"
}

// Paths adds what the user named on the command line.
func (s *Set) Paths(args []string) {
	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil {
			s.Notes = append(s.Notes, a+": "+err.Error())
			continue
		}
		if info.IsDir() {
			before := len(s.order)
			s.Walk(a, "", "argument", 64)
			if len(s.order) == before {
				s.Notes = append(s.Notes, a+": no runtime-sized binaries, Brotli libraries or Python Brotli modules inside")
			}
			continue
		}
		if sub := s.Add(a, originFor(a, ""), "argument"); sub != nil {
			s.followShim(a, sub)
		}
	}
}

// Machine adds the default places on this computer.
func (s *Set) Machine(home string) {
	t := trace("PATH")
	s.pathDirs()
	t("globs")
	j := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
	globs := []struct{ pat, via string }{
		{j(".nvm/versions/node/*/bin/node"), "nvm"},
		{j(".volta/tools/image/node/*/bin/node"), "volta"},
		{j(".local/share/fnm/node-versions/*/installation/bin/node"), "fnm"},
		{j("Library/Application Support/fnm/node-versions/*/installation/bin/node"), "fnm"},
		{j(".local/share/mise/installs/node/*/bin/node"), "mise"},
		{j(".asdf/installs/nodejs/*/bin/node"), "asdf"},
		{j("n/bin/node"), "n"},
		{"/usr/local/n/versions/node/*/bin/node", "n"},
		{j(".bun/bin/bun"), "~/.bun"},
		{j(".local/share/mise/installs/bun/*/bin/bun"), "mise"},
		{j(".deno/bin/deno"), "~/.deno"},
	}
	for _, g := range globs {
		m, _ := filepath.Glob(g.pat)
		for _, p := range m {
			s.Add(p, "runtime", g.via)
		}
	}
	appGlobs := []struct{ pat, via string }{
		{j(".local/share/claude/versions/*"), "Claude Code native install"},
		{j(".opencode/bin/opencode"), "OpenCode install"},
		{j(".local/share/cursor-agent/versions/*/*"), "Cursor agent install"},
		{j(".codeium/windsurf/bin/*"), "Windsurf"},
	}
	for _, g := range appGlobs {
		m, _ := filepath.Glob(g.pat)
		for _, p := range m {
			if info, err := os.Stat(p); err == nil {
				if info.IsDir() {
					s.Walk(p, "app", g.via, 4)
				} else if Interesting(p, info) {
					s.Add(p, "app", g.via)
				}
			}
		}
	}
	t("global packages")
	// Global JS package trees: native binaries shipped inside npm/pnpm packages.
	for _, r := range []string{j(".local/lib/node_modules"), "/usr/local/lib/node_modules", "/usr/lib/node_modules",
		"/opt/homebrew/lib/node_modules", j(".npm-global/lib/node_modules"), "/usr/local/lib/pnpm", j(".local/share/pnpm"),
		j(".bun/install/global/node_modules"), j("AppData/Roaming/npm/node_modules")} {
		s.Walk(r, "", "global packages "+r, 9)
	}
	t("app bundles")
	// App bundles.
	for _, r := range s.appRoots(home) {
		s.Walk(r, "app", "apps "+filepath.Dir(r), 8)
	}
	t("python")
	s.python(home)
	t("mcp configs")
	s.mcp(home)
	t("")
}

// trace prints how long each discovery phase took when LOTSTAMP_TRACE is set.
func trace(first string) func(next string) {
	if os.Getenv("LOTSTAMP_TRACE") == "" {
		return func(string) {}
	}
	name, start := first, time.Now()
	return func(next string) {
		fmt.Fprintf(os.Stderr, "lotstamp trace: %-16s %v\n", name, time.Since(start).Round(time.Millisecond))
		name, start = next, time.Now()
	}
}

func (s *Set) appRoots(home string) []string {
	var roots []string
	add := func(dir string) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() && looksLikeApp(p) {
				roots = append(roots, p)
			}
		}
	}
	for _, d := range []string{"/opt", "/usr/share", "/usr/lib", "/snap", "/Applications", filepath.Join(home, "Applications"),
		filepath.Join(home, ".local/share"), filepath.Join(home, "AppData/Local/Programs"), `C:\Program Files`} {
		add(d)
	}
	for _, pat := range []string{"*.AppImage", "Applications/*.AppImage", "Downloads/*.AppImage", ".local/bin/*.AppImage"} {
		m, _ := filepath.Glob(filepath.Join(home, pat))
		for _, p := range m {
			s.Add(p, "app", "AppImage")
		}
	}
	return roots
}

// looksLikeApp is true for directories that hold an Electron/Chromium-style app (resources.pak,
// app.asar, an .app bundle) or a single big executable near the top.
func looksLikeApp(dir string) bool {
	if strings.HasSuffix(dir, ".app") {
		return true
	}
	hit := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || hit {
			return filepath.SkipDir
		}
		if d.IsDir() && strings.Count(p, string(filepath.Separator))-strings.Count(dir, string(filepath.Separator)) >= 3 {
			return filepath.SkipDir
		}
		n := d.Name()
		if n == "resources.pak" || n == "app.asar" || n == "chrome_100_percent.pak" || n == "icudtl.dat" {
			hit = true
			return filepath.SkipAll
		}
		return nil
	})
	return hit
}

func (s *Set) pathDirs() {
	seen := map[string]bool{}
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" || seen[d] || isSystemDir(d) {
			continue
		}
		seen[d] = true
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			if runtime.GOOS == "windows" {
				// only .exe can be a runtime and only .cmd can be an npm shim; opening every
				// other file on PATH is slow under on-access antivirus scanning
				ext := strings.ToLower(filepath.Ext(p))
				if ext != ".exe" && ext != ".cmd" {
					continue
				}
			}
			info, err := os.Stat(p) // follows symlinks
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if info.Size() < 64<<10 && isScript(p) {
				s.followShim(p, nil) // npm/pnpm/bun shims are tiny scripts
				continue
			}
			if Interesting(p, info) {
				s.Add(p, originFor(p, ""), "PATH "+p)
			}
		}
	}
}

var shimPath = regexp.MustCompile(`["']?((?:\$\{?basedir\}?|\$\(dirname "\$0"\)|%~dp0|%dp0%|/)[^"'\s]*)["']?`)

// isSystemDir is true for the Windows system folders that sit on every PATH. Nothing in
// them embeds a Brotli decoder for JavaScript, and they hold thousands of files.
func isSystemDir(d string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	d, root = strings.ToLower(filepath.Clean(d)), strings.ToLower(filepath.Clean(root))
	return d == root || strings.HasPrefix(d, root+`\`)
}

func isScript(p string) bool {
	if strings.HasSuffix(strings.ToLower(p), ".cmd") {
		return true
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 2)
	n, _ := io.ReadFull(f, b)
	return n == 2 && b[0] == '#' && b[1] == '!'
}

// followShim reads a small launcher script (npm/pnpm/bun shims, wrapper scripts) and adds the
// binary it starts, if that binary is runtime-sized.
func (s *Set) followShim(p string, _ *verdict.Subject) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	f.Close()
	if len(b) < 2 || !(b[0] == '#' && b[1] == '!' || strings.HasSuffix(strings.ToLower(p), ".cmd")) {
		return
	}
	dir := filepath.Dir(p)
	if b[0] == '#' {
		// skip the shebang line: its interpreter is found on PATH on its own
		if i := strings.IndexByte(string(b), '\n'); i > 0 {
			b = b[i:]
		}
	}
	for _, m := range shimPath.FindAllStringSubmatch(string(b), -1) {
		t := m[1]
		for _, pre := range []string{"${basedir}", "$basedir", `$(dirname "$0")`, "%~dp0", "%dp0%"} {
			if strings.HasPrefix(t, pre) {
				t = filepath.Join(dir, strings.TrimPrefix(t, pre))
			}
		}
		t = filepath.FromSlash(strings.ReplaceAll(t, `\`, "/"))
		if !filepath.IsAbs(t) {
			continue
		}
		info, err := os.Stat(t)
		if err != nil || !info.Mode().IsRegular() || !Interesting(t, info) {
			continue
		}
		s.Add(t, originFor(t, ""), "PATH "+p+" (launcher script)")
	}
}

// python adds Brotli extension modules from site-packages directories.
func (s *Set) python(home string) {
	pats := []string{
		filepath.Join(home, ".local/lib/python3*/site-packages"),
		"/usr/lib/python3*/dist-packages", "/usr/lib/python3*/site-packages", "/usr/local/lib/python3*/*-packages",
		"/usr/lib64/python3*/site-packages", "/opt/homebrew/lib/python3*/site-packages",
		filepath.Join(home, "Library/Python/*/lib/python/site-packages"),
		filepath.Join(home, ".local/share/uv/tools/*/lib/python3*/site-packages"),
		filepath.Join(home, ".local/share/pipx/venvs/*/lib/python3*/site-packages"),
		filepath.Join(home, ".local/pipx/venvs/*/lib/python3*/site-packages"),
		filepath.Join(home, ".cache/uv/archive-v0/*/lib/python3*/site-packages"),
		filepath.Join(home, ".virtualenvs/*/lib/python3*/site-packages"),
		filepath.Join(home, ".pyenv/versions/*/lib/python3*/site-packages"),
		filepath.Join(home, "miniconda3/lib/python3*/site-packages"),
		filepath.Join(home, "anaconda3/lib/python3*/site-packages"),
		filepath.Join(home, "AppData/Roaming/Python/Python3*/site-packages"),
		".venv/lib/python3*/site-packages", "venv/lib/python3*/site-packages",
	}
	for _, pat := range pats {
		dirs, _ := filepath.Glob(pat)
		for _, d := range dirs {
			s.SitePackages(d, "python "+d)
		}
	}
}

var distInfo = regexp.MustCompile(`^(?i)(brotli|brotlicffi)-([0-9][0-9a-z.]*)\.(?:dist|egg)-info$`)

// SitePackages adds the Brotli extension modules in one site-packages directory.
func (s *Set) SitePackages(dir, via string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	vers := map[string]string{}
	for _, e := range ents {
		if m := distInfo.FindStringSubmatch(e.Name()); m != nil {
			vers[strings.ToLower(m[1])] = m[2]
		}
	}
	add := func(p, dist string) {
		sub := s.Add(p, "runtime", via)
		if sub != nil {
			sub.PyDist = map[string]string{"brotli": "brotli", "brotlicffi": "brotlicffi"}[dist]
			sub.PyVer = vers[dist]
			sub.Label = "Python " + dist + " " + vers[dist]
		}
	}
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, "_brotli.") && isPyBrotli(n) {
			add(filepath.Join(dir, e.Name()), "brotli")
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "brotlicffi", "_brotlicffi*")); len(m) > 0 {
		for _, p := range m {
			if isPyBrotli(strings.ToLower(filepath.Base(p))) {
				add(p, "brotlicffi")
			}
		}
	}
}

// pyInfo recognises a Python Brotli extension module and reads its version from the
// dist-info folder next to it (site-packages/_brotli*.so, site-packages/brotlicffi/_brotlicffi*.so).
func pyInfo(p string) (dist, ver string) {
	b := strings.ToLower(filepath.Base(p))
	if !isPyBrotli(b) {
		return "", ""
	}
	dir := filepath.Dir(p)
	dist = "brotli"
	if strings.HasPrefix(b, "_brotlicffi") {
		dist, dir = "brotlicffi", filepath.Dir(dir)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if m := distInfo.FindStringSubmatch(e.Name()); m != nil && strings.ToLower(m[1]) == dist {
			ver = m[2]
		}
	}
	return dist, ver
}

// Sorted returns subjects ordered by path, for stable output.
func Sorted(subs []verdict.Subject) []verdict.Subject {
	sort.SliceStable(subs, func(i, j int) bool { return subs[i].Path < subs[j].Path })
	return subs
}
