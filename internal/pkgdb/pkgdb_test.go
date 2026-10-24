package pkgdb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompareDeb(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.9-2+b6", "1.0.9-2+deb12u1", -1}, // the bookworm case: +b6 is a binNMU of the old source
		{"1.0.9-2+deb12u1", "1.0.9-2+deb12u1", 0},
		{"1.1.0-2+b7", "1.1.0-2+deb13u1", -1},
		{"1.1.0-2+deb13u2", "1.1.0-2+deb13u1", 1},
		{"1.2.0-4+b1", "1.2.1-1", -1},
		{"1.2.1~rc1-1", "1.2.1-1", -1},
		{"1:1.0-1", "2.0-1", 1},
		{"1.10", "1.9", 1},
	} {
		if got := CompareDeb(c.a, c.b); got != c.want {
			t.Errorf("CompareDeb(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func fakeRoot(t *testing.T, osRelease, list, status string) {
	t.Helper()
	r := t.TempDir()
	os.MkdirAll(filepath.Join(r, "etc"), 0o755)
	os.MkdirAll(filepath.Join(r, "var/lib/dpkg/info"), 0o755)
	os.WriteFile(filepath.Join(r, "etc/os-release"), []byte(osRelease), 0o644)
	os.WriteFile(filepath.Join(r, "var/lib/dpkg/info/libbrotli1:amd64.list"), []byte(list), 0o644)
	os.WriteFile(filepath.Join(r, "var/lib/dpkg/status"), []byte(status), 0o644)
	old := Root
	Root = r
	t.Cleanup(func() { Root = old })
}

func TestDpkgOwner(t *testing.T) {
	fakeRoot(t, "ID=debian\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"/.\n/usr\n/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9\n",
		"Package: libbrotli0\nStatus: install ok installed\nVersion: 0.6\n\nPackage: libbrotli1\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0.9-2+b6\n\n")
	o := ReadOS()
	if o.ID != "debian" || o.Codename != "bookworm" {
		t.Fatalf("os %+v", o)
	}
	// usr-merge: the library is reached as /lib/... but listed as /usr/lib/...
	p, ok := DpkgOwner("/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9")
	if !ok || p.Name != "libbrotli1" || p.Version != "1.0.9-2+b6" || p.Arch != "amd64" {
		t.Fatalf("owner %+v %v", p, ok)
	}
	if _, ok := DpkgOwner("/usr/bin/other"); ok {
		t.Fatal("unowned file matched")
	}
}

func TestSidFallback(t *testing.T) {
	fakeRoot(t, "ID=debian\n", "", "")
	os.WriteFile(filepath.Join(Root, "etc/debian_version"), []byte("forky/sid\n"), 0o644)
	if o := ReadOS(); o.Codename != "sid" {
		t.Fatalf("codename %q", o.Codename)
	}
}
