package pkgdb

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// OS describes the distro from /etc/os-release.
type OS struct {
	ID       string // debian, ubuntu, alpine...
	Codename string // bookworm, trixie...
	Pretty   string
}

// Root lets tests point the readers at a fake filesystem.
var Root = "/"

func ReadOS() OS {
	var o OS
	f, err := os.Open(filepath.Join(Root, "etc/os-release"))
	if err != nil {
		return o
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			o.ID = v
		case "VERSION_CODENAME":
			o.Codename = v
		case "PRETTY_NAME":
			o.Pretty = v
		}
	}
	if o.ID == "debian" && o.Codename == "" {
		// testing/sid images often lack VERSION_CODENAME; debian_version says "forky/sid".
		if b, err := os.ReadFile(filepath.Join(Root, "etc/debian_version")); err == nil {
			if strings.Contains(string(b), "sid") {
				o.Codename = "sid"
			}
		}
	}
	return o
}

// Pkg is one installed package that owns a file.
type Pkg struct {
	Manager string // dpkg
	Name    string
	Version string
	Arch    string
}

// DpkgOwner finds the installed dpkg package whose file list contains path (or the same file
// under the /usr merge). It reads /var/lib/dpkg only; it never runs dpkg.
func DpkgOwner(path string) (Pkg, bool) {
	info := filepath.Join(Root, "var/lib/dpkg/info")
	lists, _ := filepath.Glob(filepath.Join(info, "*.list"))
	want := map[string]bool{path: true}
	if strings.HasPrefix(path, "/usr/lib/") {
		want[strings.TrimPrefix(path, "/usr")] = true
	} else if strings.HasPrefix(path, "/lib/") {
		want["/usr"+path] = true
	}
	for _, l := range lists {
		base := filepath.Base(l)
		if !strings.Contains(base, "brotli") && !strings.Contains(base, "node") {
			continue // cheap: only packages that could own a Brotli decoder
		}
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		hit := false
		for s.Scan() {
			if want[s.Text()] {
				hit = true
				break
			}
		}
		f.Close()
		if hit {
			name := strings.TrimSuffix(base, ".list")
			arch := ""
			if n, a, ok := strings.Cut(name, ":"); ok {
				name, arch = n, a
			}
			if v, ok := dpkgVersion(name, arch); ok {
				return Pkg{Manager: "dpkg", Name: name, Version: v, Arch: arch}, true
			}
		}
	}
	return Pkg{}, false
}

func dpkgVersion(name, arch string) (string, bool) {
	f, err := os.Open(filepath.Join(Root, "var/lib/dpkg/status"))
	if err != nil {
		return "", false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	var pkg, ar, ver, status string
	flush := func() (string, bool) {
		if pkg == name && (arch == "" || ar == arch || ar == "all") && strings.HasSuffix(status, " installed") {
			return ver, true
		}
		return "", false
	}
	for s.Scan() {
		line := s.Text()
		if line == "" {
			if v, ok := flush(); ok {
				return v, true
			}
			pkg, ar, ver, status = "", "", "", ""
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch k {
		case "Package":
			pkg = v
		case "Architecture":
			ar = v
		case "Version":
			ver = v
		case "Status":
			status = v
		}
	}
	return flush()
}
