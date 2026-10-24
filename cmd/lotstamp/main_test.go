package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/lotstamp/internal/testfix"
)

type doc struct {
	Findings []struct {
		Status  string `json:"status"`
		Label   string `json:"label"`
		Kind    string `json:"kind"`
		Runtime string `json:"runtime"`
		But     string `json:"but"`
		Who     string `json:"who"`
		Fix     string `json:"fix"`
	} `json:"findings"`
}

func scanJSON(t *testing.T, args ...string) (doc, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"--json"}, args...), &out, &errb)
	var d doc
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("json: %v\n%s\n%s", err, out.String(), errb.String())
	}
	return d, code
}

func one(t *testing.T, rel string, s testfix.Spec) (doc, int) {
	t.Helper()
	d := t.TempDir()
	return scanJSON(t, testfix.Write(t, d, rel, s))
}

func TestNodeLines(t *testing.T) {
	for _, c := range []struct {
		v      string
		fixed  bool
		status string
		code   int
	}{
		{"24.22.0", false, "BEHIND", 3},
		{"24.22.1", true, "FIXED", 0},
		{"22.23.4", true, "FIXED", 0},
		{"20.19.5", false, "NO-FIX-LINE", 3},
	} {
		d, code := one(t, "node-v"+c.v+"-linux-x64/bin/node", testfix.Spec{Table: true, Fixed: c.fixed, Extra: testfix.NodeHeaders(c.v)})
		if len(d.Findings) != 1 || d.Findings[0].Status != c.status || code != c.code {
			t.Errorf("node %s: %+v exit %d", c.v, d.Findings, code)
		}
	}
}

// Bun binaries carry a node-v26.3.0 headers URL; a Node-version check calls them fixed or not
// by the wrong number. The Bun version and the decoder decide.
func TestBunTrap(t *testing.T) {
	d, code := one(t, "bun", testfix.Spec{Table: true, Extra: "Bun/1.4.3\x00" + testfix.NodeHeaders("26.3.0")})
	if code != 3 || d.Findings[0].Status != "BEHIND" || d.Findings[0].Runtime != "Bun 1.4.3" || !strings.Contains(d.Findings[0].Fix, "1.4.4") {
		t.Fatalf("%+v exit %d", d.Findings, code)
	}
	d, code = one(t, "bun", testfix.Spec{Table: true, Fixed: true, Extra: "Bun/1.4.4\x00" + testfix.NodeHeaders("26.3.0")})
	if code != 0 || d.Findings[0].Status != "FIXED" {
		t.Fatalf("%+v exit %d", d.Findings, code)
	}
}

// Electron editors show an unpatched Node version, but their decoder is Chromium's.
func TestElectronLooksOld(t *testing.T) {
	d, code := one(t, "Cursor/cursor", testfix.Spec{Table: true, Fixed: true,
		Extra: testfix.NodeHeaders("24.19.0") + "\x00Electron/39.2.0\x00Chrome/148.0.7400.5\x00"})
	f := d.Findings[0]
	if code != 0 || f.Status != "FIXED" || f.Label != "Cursor" || !strings.Contains(f.But, "Chromium") {
		t.Fatalf("%+v exit %d", f, code)
	}
}

func TestVendorBinary(t *testing.T) {
	d, _ := one(t, "VSCode-linux-x64/resources/app/node_modules.asar.unpacked/@vscode/vsce-sign/bin/node", testfix.Spec{Table: true})
	f := d.Findings[0]
	if f.Status != "BEHIND" {
		t.Fatalf("%+v", f)
	}
}

func TestAppImageUnknown(t *testing.T) {
	dir := t.TempDir()
	b := testfix.Bytes(testfix.Spec{})
	copy(b[8:], "AI\x02")
	p := filepath.Join(dir, "node")
	os.WriteFile(p, b, 0o755)
	d, code := scanJSON(t, p)
	if d.Findings[0].Status != "UNKNOWN" || code != 0 {
		t.Fatalf("%+v exit %d", d.Findings, code)
	}
	if _, code = scanJSON(t, "--fail-on", "unknown", p); code != 3 {
		t.Fatalf("--fail-on unknown exit %d", code)
	}
	if _, code = scanJSON(t, p, "--fail-on", "never"); code != 0 {
		t.Fatalf("--fail-on never exit %d", code)
	}
}

func TestPythonBrotli(t *testing.T) {
	dir := t.TempDir()
	testfix.Write(t, dir, "site-packages/_brotli.cpython-313-x86_64-linux-gnu.so", testfix.Spec{Table: true})
	testfix.File(t, dir, "site-packages/Brotli-1.2.0.dist-info/METADATA", "Name: Brotli\nVersion: 1.2.0\n")
	d, code := scanJSON(t, filepath.Join(dir, "site-packages"))
	if code != 3 || len(d.Findings) != 1 || !strings.Contains(d.Findings[0].Fix, "brotli>=1.2.1") {
		t.Fatalf("%+v exit %d", d.Findings, code)
	}
}

func TestBareLibrary(t *testing.T) {
	dir := t.TempDir()
	old := testfix.Write(t, dir, "old/libbrotlidec.so.1.0.9", testfix.Spec{Table: true, Bare: true})
	fixed := testfix.Write(t, dir, "new/libbrotlidec.so.1.0.9", testfix.Spec{Table: true, Bare: true, Fixed: true})
	d, _ := scanJSON(t, old)
	if d.Findings[0].Status != "BEHIND" {
		t.Fatalf("old %+v", d.Findings)
	}
	d, _ = scanJSON(t, fixed)
	if d.Findings[0].Status != "FIXED" {
		t.Fatalf("fixed %+v", d.Findings)
	}
}

func TestTextAndUsage(t *testing.T) {
	dir := t.TempDir()
	p := testfix.Write(t, dir, "node-v24.22.0-linux-x64/bin/node", testfix.Spec{Table: true, Extra: testfix.NodeHeaders("24.22.0")})
	var out, errb bytes.Buffer
	if code := run([]string{"--no-color", p}, &out, &errb); code != 3 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{"nothing was executed", "BEHIND", "Node 24.22.0", "24.22.1", "1 behind"} {
		if !strings.Contains(s, want) {
			t.Errorf("text output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b[") {
		t.Error("--no-color printed escapes")
	}
	out.Reset()
	if code := run([]string{"--fail-on", "sometimes"}, &out, &errb); code != 64 {
		t.Fatalf("bad flag exit %d", code)
	}
	if code := run([]string{"--nope"}, &out, &errb); code != 64 {
		t.Fatalf("unknown flag exit %d", code)
	}
	errb.Reset()
	if code := run([]string{filepath.Join(dir, "missing")}, &out, &errb); code != 1 {
		t.Fatalf("missing path exit %d", code)
	}
	out.Reset()
	run([]string{"version"}, &out, &errb)
	if !strings.HasPrefix(out.String(), "lotstamp ") {
		t.Fatalf("version: %q", out.String())
	}
	out.Reset()
	run([]string{"advisory"}, &out, &errb)
	if !strings.Contains(out.String(), "CVE-2026-111497") {
		t.Fatalf("advisory: %q", out.String())
	}
}

// LOTSTAMP_DOGFOOD points at a folder of real downloaded runtimes (CI fills it).
func TestDogfood(t *testing.T) {
	root := os.Getenv("LOTSTAMP_DOGFOOD")
	if root == "" {
		t.Skip("LOTSTAMP_DOGFOOD not set")
	}
	want := map[string]string{
		"node-v24.22.0-linux-x64/bin/node": "BEHIND",
		"node-v24.22.1-linux-x64/bin/node": "FIXED",
		"node-v20.19.5-linux-x64/bin/node": "NO-FIX-LINE",
		"bun-1.4.3/bun-linux-x64/bun":      "BEHIND",
		"bun-1.4.4/bun-linux-x64/bun":      "FIXED",
		"deb/x-libbrotli1_1.0.9-2+b6/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9":      "BEHIND",
		"deb/x-libbrotli1_1.0.9-2+deb12u1/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9": "FIXED",
	}
	for rel, st := range want {
		p := filepath.Join(root, rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s missing", rel)
			continue
		}
		d, _ := scanJSON(t, p)
		if len(d.Findings) != 1 || d.Findings[0].Status != st {
			t.Errorf("%s: want %s, got %+v", rel, st, d.Findings)
		}
	}
}
