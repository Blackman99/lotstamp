// Package verdict turns evidence into an answer a person can act on: is the decoder this
// thing runs fixed, how do we know, and who has to ship the fix.
package verdict

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Blackman99/lotstamp/internal/advisory"
	"github.com/Blackman99/lotstamp/internal/pkgdb"
	"github.com/Blackman99/lotstamp/internal/probe"
)

type Status string

const (
	Fixed     Status = "FIXED"
	Behind    Status = "BEHIND"
	NoFixLine Status = "NO-FIX-LINE"
	Unknown   Status = "UNKNOWN"
	Absent    Status = "NO-DECODER"
)

// Rank orders statuses from most to least urgent.
func Rank(s Status) int {
	switch s {
	case NoFixLine:
		return 0
	case Behind:
		return 1
	case Unknown:
		return 2
	case Fixed:
		return 3
	}
	return 4
}

// Kind of thing carrying the decoder.
const (
	KindNode     = "node"
	KindBun      = "bun"
	KindElectron = "electron"
	KindPython   = "python"
	KindSystem   = "system-lib"
	KindOther    = "binary"
)

// Subject is what discovery knows about a file before it is read.
type Subject struct {
	Path    string   // as found
	Real    string   // symlinks resolved
	Origin  string   // "runtime" (you installed the runtime itself) or "app" (it ships inside something)
	Label   string   // "Claude Code 2.1.310", "VS Code", ...
	Via     []string // how it was found: "PATH: /usr/local/bin/bun (pnpm shim)"
	MCP     []string // MCP servers launched with it
	PyDist  string   // python distribution name (brotli / brotlicffi) when from site-packages
	PyVer   string
	UsedBy  []string // for shared libraries: binaries that link it
	SysLib  bool
	Package *pkgdb.Pkg
}

type Finding struct {
	Status   Status          `json:"status"`
	Path     string          `json:"path"`
	Label    string          `json:"label"`
	Kind     string          `json:"kind"`
	Runtime  string          `json:"runtime,omitempty"` // "Node 24.22.0", "Bun 1.4.4", "Electron 42.11.16 · Chromium 148"
	Decoder  string          `json:"decoder"`           // human evidence about the decoder code
	Says     string          `json:"version_says,omitempty"`
	But      string          `json:"but,omitempty"`
	Fix      string          `json:"fix,omitempty"`
	Who      string          `json:"who,omitempty"` // you, vendor, distro
	Via      []string        `json:"found_via,omitempty"`
	MCP      []string        `json:"mcp,omitempty"`
	UsedBy   []string        `json:"used_by,omitempty"`
	Package  string          `json:"package,omitempty"`
	Evidence *probe.Evidence `json:"evidence"`
}

// Judge decides one file.
func Judge(a *advisory.Advisory, s Subject, ev *probe.Evidence, osr pkgdb.OS) Finding {
	f := Finding{Path: s.Path, Label: s.Label, Evidence: ev, Via: s.Via, MCP: s.MCP, UsedBy: s.UsedBy, Kind: KindOther}
	if f.Label == "" {
		f.Label = filepath.Base(s.Path)
	}
	has := ev.HasDecoder(a.MinDecoder)
	switch {
	case ev.FixMarker:
		f.Decoder = fmt.Sprintf("fixed code: %s present (%d decoder error names)", strings.TrimPrefix(a.FixMarker, "_ERROR_FORMAT_"), ev.DecoderNames)
	case has:
		f.Decoder = fmt.Sprintf("pre-fix code: %d decoder error names, no %s", ev.DecoderNames, strings.TrimPrefix(a.FixMarker, "_ERROR_FORMAT_"))
	default:
		f.Decoder = "no Brotli decoder compiled in"
	}

	// Identity, most specific first. Bun binaries also contain a node-v26.3.0 headers URL
	// (Bun's Node compatibility level), so Bun must win over Node.
	switch {
	case s.SysLib:
		f.Kind = KindSystem
	case s.PyDist != "":
		f.Kind = KindPython
		f.Runtime = "Python " + s.PyDist + " " + s.PyVer
	case len(ev.Bun) > 0:
		f.Kind = KindBun
		f.Runtime = "Bun " + ev.Bun[0]
		if len(ev.Node) > 0 {
			f.Says = "contains a Node " + ev.Node[0] + " headers URL"
			f.But = "that is Bun's Node-compat level; the runtime is Bun " + ev.Bun[0]
		}
	case len(ev.Electron) > 0:
		f.Kind = KindElectron
		f.Runtime = "Electron " + ev.Electron[0]
		if len(ev.Chrome) > 0 {
			f.Runtime += " · Chromium " + fmt.Sprint(advisory.Major(ev.Chrome[0]))
		}
		if len(ev.Node) > 0 {
			f.Runtime += " · Node " + ev.Node[0]
		}
	case len(ev.Node) > 0:
		f.Kind = KindNode
		f.Runtime = "Node " + ev.Node[0]
	}
	if f.Kind == KindOther && ev.HasDecoder(a.MinDecoder) {
		f.Runtime = "a Brotli decoder compiled into a native program; whether untrusted Brotli data can reach it depends on the program"
	}

	if ev.Packed != "" && !has {
		f.Status = Unknown
		f.Decoder = "AppImage: payload is compressed, nothing to read"
		f.Fix = "extract it (./App.AppImage --appimage-extract) and run: lotstamp squashfs-root"
		f.Who = "you"
		return f
	}

	if s.SysLib {
		return judgeSysLib(a, s, f, ev, has, osr)
	}

	if !has && !ev.FixMarker {
		f.Status = Absent
		return f
	}

	if ev.FixMarker {
		f.Status = Fixed
		switch f.Kind {
		case KindElectron:
			if len(ev.Node) > 0 && a.NodeFixFor(ev.Node[0]) != "" && advisory.Cmp(ev.Node[0], a.NodeFixFor(ev.Node[0])) < 0 {
				f.Says = "embeds Node " + ev.Node[0] + " (fix is " + a.NodeFixFor(ev.Node[0]) + ")"
				f.But = "Electron builds Node against Chromium's Brotli, and Chromium " + chromeMajor(ev) + " already has the fix"
			}
		case KindPython:
			if fx := a.PyPI[strings.ToLower(s.PyDist)]; fx != "" && advisory.Cmp(s.PyVer, fx) < 0 {
				f.Says = s.PyDist + " " + s.PyVer + " (first release with the fix: " + fx + ")"
				f.But = "this build's bundled decoder already carries the fix"
			}
		}
		return f
	}

	// Pre-fix decoder code.
	f.Status = Behind
	switch f.Kind {
	case KindNode:
		v := ev.Node[0]
		if fx := a.NodeFixFor(v); fx != "" {
			f.Fix = "upgrade to Node " + fx + " or newer on the " + fmt.Sprint(advisory.Major(v)) + ".x line"
			if cmd := nodeManagerFix(s.Real, advisory.Major(v), fx); cmd != "" {
				f.Fix = cmd + "  (Node " + fx + " or newer on the " + fmt.Sprint(advisory.Major(v)) + ".x line)"
			}
		} else {
			f.Status = NoFixLine
			f.Fix = "Node " + fmt.Sprint(advisory.Major(v)) + ".x gets no fix; move to " + a.Node.Advice
		}
	case KindBun:
		f.Fix = "Bun " + a.Bun.Fixed + " or newer has the fix"
	case KindElectron:
		f.Fix = "needs an Electron release on Chromium " + fmt.Sprint(a.Electron.FixedChromiumMajor) + "+"
	case KindPython:
		dist := strings.ToLower(s.PyDist)
		f.Fix = fmt.Sprintf("pip install -U '%s>=%s' in that environment", dist, a.PyPI[dist])
		if py := pythonFor(s.Real); py != "" {
			f.Fix = fmt.Sprintf("%s -U '%s>=%s'", py, dist, a.PyPI[dist])
		}
	default:
		f.Fix = "rebuild against Brotli " + strings.Join(a.UpstreamFixed, " / ")
	}
	if s.Origin == "app" && (f.Kind == KindNode || f.Kind == KindBun || f.Kind == KindElectron || f.Kind == KindOther) {
		f.Who = "vendor"
		upd := "update " + strings.Split(f.Label, " · ")[0]
		if pkg := npmGlobalPkg(s.Real); pkg != "" {
			upd = "npm install -g " + pkg + "@latest"
		}
		f.Fix = upd + "; if the latest still reads BEHIND, the vendor has to ship a rebuild (" + f.Fix + ")"
		if f.Status == NoFixLine {
			f.Status = Behind
		}
	} else {
		f.Who = "you"
		if f.Kind == KindBun {
			switch {
			case strings.Contains(filepath.ToSlash(s.Real), "/.pnpm/"):
				f.Fix = "pnpm add -g bun@latest  (" + f.Fix + ")"
			case npmGlobalPkg(s.Real) == "bun":
				f.Fix = "npm install -g bun@latest  (" + f.Fix + ")"
			default:
				f.Fix = "bun upgrade, or reinstall it the way you installed it (" + f.Fix + ")"
			}
		}
	}
	return f
}

func chromeMajor(ev *probe.Evidence) string {
	if len(ev.Chrome) == 0 {
		return "≥148"
	}
	return fmt.Sprint(advisory.Major(ev.Chrome[0]))
}

func judgeSysLib(a *advisory.Advisory, s Subject, f Finding, ev *probe.Evidence, has bool, osr pkgdb.OS) Finding {
	f.Runtime = "system Brotli decoder library"
	if s.Package != nil {
		f.Package = s.Package.Name + " " + s.Package.Version
		f.Runtime = "system " + f.Package
	}
	d, known := a.Distros[osr.ID]
	if s.Package != nil && s.Package.Manager == "dpkg" && known && osr.Codename != "" {
		if fx, ok := d.Fixed[osr.Codename]; ok {
			adv := d.Advisories[osr.Codename]
			if pkgdb.CompareDeb(s.Package.Version, fx) >= 0 {
				f.Status = Fixed
				if has && !ev.FixMarker {
					f.Says = "decoder code has no " + strings.TrimPrefix(a.FixMarker, "_ERROR_FORMAT_")
					f.But = fmt.Sprintf("package %s ≥ %s (%s) is marked fixed by %s, and the package database decides", s.Package.Version, fx, adv, osr.ID)
				}
				return f
			}
			f.Status = Behind
			f.Who = "you"
			f.Fix = fmt.Sprintf("sudo apt update && sudo apt install --only-upgrade %s  (fixed in %s, %s)", s.Package.Name, fx, adv)
			return f
		}
		for _, u := range d.Unfixed {
			if u == osr.Codename {
				if ev.FixMarker {
					f.Status = Fixed
					return f
				}
				f.Status = Behind
				f.Who = "distro"
				f.Fix = osr.Codename + " has no fixed " + d.Package + " yet; watch " + a.Links[len(a.Links)-1]
				return f
			}
		}
	}
	// Homebrew and plain installs: the upstream version is in the path.
	if v := cellarVersion(s.Real); v != "" {
		f.Runtime = "Homebrew brotli " + v
		if a.UpstreamIsFixed(v) || ev.FixMarker {
			f.Status = Fixed
			return f
		}
		f.Status = Behind
		f.Who = "you"
		f.Fix = "brew upgrade brotli (fixed in " + a.UpstreamFixFor(v) + ")"
		return f
	}
	switch {
	case ev.FixMarker:
		f.Status = Fixed
	case has:
		f.Status = Behind
		f.Who = "distro"
		f.Fix = "update the brotli package or bundle that ships this library (fixed upstream in " + strings.Join(a.UpstreamFixed, " / ") + ")"
		if osr.Pretty != "" && (strings.HasPrefix(s.Real, "/usr/") || strings.HasPrefix(s.Real, "/lib")) {
			f.Fix = "update the brotli package from " + osr.Pretty + " (Debian's backports add the new error name too, so an updated library reads FIXED)"
		}
	default:
		f.Status = Unknown
		f.Decoder = "no decoder error table found in the library"
	}
	return f
}

func cellarVersion(p string) string {
	i := strings.Index(p, "/Cellar/brotli/")
	if i < 0 {
		return ""
	}
	rest := p[i+len("/Cellar/brotli/"):]
	v, _, _ := strings.Cut(rest, "/")
	v, _, _ = strings.Cut(v, "_")
	return v
}

// nodeManagerFix names the command for the version manager that owns this node, if any.
func nodeManagerFix(real string, major int, fx string) string {
	p := filepath.ToSlash(real)
	m := fmt.Sprint(major)
	switch {
	case strings.Contains(p, "/.nvm/versions/node/"):
		return "nvm install " + m + " && nvm alias default " + m
	case strings.Contains(p, "/.volta/tools/image/node/"):
		return "volta install node@" + m
	case strings.Contains(p, "/fnm/node-versions/") || strings.Contains(p, "/.fnm/node-versions/"):
		return "fnm install " + m + " && fnm default " + m
	case strings.Contains(p, "/mise/installs/node/"):
		return "mise use -g node@" + fx
	case strings.Contains(p, "/.asdf/installs/nodejs/"):
		return "asdf install nodejs " + fx + " && asdf global nodejs " + fx
	case strings.Contains(p, "/n/versions/node/"):
		return "n " + fx
	case strings.Contains(p, "/Cellar/node"):
		return "brew upgrade node"
	}
	return ""
}

// pythonFor names the pip invocation for the environment that owns a site-packages directory.
func pythonFor(real string) string {
	p := filepath.ToSlash(real)
	i := strings.Index(p, "/site-packages/")
	if i < 0 {
		return ""
	}
	lib := p[:i] // .../lib/python3.13
	ver := path.Base(lib)
	if !strings.HasPrefix(ver, "python3") {
		return ""
	}
	root := path.Dir(path.Dir(lib)) // venv root, ~/.local, /usr/local
	if strings.HasSuffix(root, "/.local") {
		return ver + " -m pip install --user"
	}
	if b := root + "/bin/" + ver; fileExists(b) {
		return b + " -m pip install"
	}
	if b := root + "/bin/python"; fileExists(b) {
		return b + " -m pip install"
	}
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// npmGlobalPkg returns the package name for files inside a global node_modules tree.
func npmGlobalPkg(real string) string {
	p := filepath.ToSlash(real)
	i := strings.Index(p, "/lib/node_modules/")
	if i < 0 || strings.Contains(p, "/.pnpm/") {
		return ""
	}
	rest := strings.Split(p[i+len("/lib/node_modules/"):], "/")
	if len(rest) > 1 && strings.HasPrefix(rest[0], "@") {
		return rest[0] + "/" + rest[1]
	}
	return rest[0]
}
