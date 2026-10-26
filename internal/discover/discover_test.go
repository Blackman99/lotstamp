package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/lotstamp/internal/testfix"
)

func TestShimFollowing(t *testing.T) {
	d := t.TempDir()
	target := testfix.Write(t, d, "lib/pnpm/5/.pnpm/bun@1.4.2/node_modules/bun/bin/bun.exe", testfix.Spec{Table: true})
	shim := testfix.File(t, d, "bin/bun", `
#!/bin/sh
basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")
exec "$basedir/../lib/pnpm/5/.pnpm/bun@1.4.2/node_modules/bun/bin/bun.exe"   "$@"
`)
	s := NewSet()
	s.Paths([]string{shim})
	var found bool
	want, _ := os.Stat(target)
	for _, sub := range s.Subjects() {
		if st, err := os.Stat(sub.Real); err == nil && os.SameFile(st, want) {
			found = true
			if sub.Label != "bun 1.4.2 (package)" || sub.Origin != "runtime" {
				t.Fatalf("label %q origin %q", sub.Label, sub.Origin)
			}
		}
	}
	if !found {
		t.Fatalf("shim not followed: %+v", s.Subjects())
	}
}

func TestHardLinksAreOneFile(t *testing.T) {
	d := t.TempDir()
	a := testfix.Write(t, d, "a/node", testfix.Spec{Table: true})
	b := filepath.Join(d, "b", "node")
	os.MkdirAll(filepath.Dir(b), 0o755)
	if err := os.Link(a, b); err != nil {
		t.Skip("no hard links here")
	}
	s := NewSet()
	s.Paths([]string{a, b})
	if n := len(s.Subjects()); n != 1 {
		t.Fatalf("got %d subjects for one inode", n)
	}
}

func TestLabels(t *testing.T) {
	for p, want := range map[string]string{
		"/home/u/.local/share/claude/versions/2.1.310":                                                   "Claude Code 2.1.310",
		"/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe":                                 "Claude Code (npm)",
		"/opt/VSCode-linux-x64/code":                                                                     "VS Code",
		"/opt/VSCode-linux-x64/resources/app/node_modules.asar.unpacked/@vscode/vsce-sign/bin/vsce-sign": "VS Code · vsce-sign",
		"/opt/node-v24.22.0-linux-x64/bin/node":                                                          "node 24.22.0 tarball",
		"C:/Users/u/AppData/Local/OpenAI/Codex/runtimes/cua_node/1fb7137c46617d50/bin/node.exe":          "Codex app computer-use node (1fb7137c46617d50)",
		"C:/Users/u/AppData/Local/OpenAI/Codex/bin/5b9024f90663758b/node.exe":                            "Codex app node (5b9024f90663758b)",
		"C:/Users/u/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe":          "Codex app codex-primary-runtime",
		"/usr/bin/somethingelse":                                                                         "somethingelse",
	} {
		if got := Label(p); got != want {
			t.Errorf("Label(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestMCP(t *testing.T) {
	d := t.TempDir()
	p := testfix.File(t, d, ".claude.json", `{"mcpServers":{"fs":{"command":"npx","args":["-y","x"]},"web":{"url":"https://x"}},
"projects":{"/home/u/app":{"mcpServers":{"db":{"command":"bunx"}}}}}`)
	got := ReadMCP(p)
	if len(got) != 2 || got[0].Name != "fs" || got[1].Name != "db (app)" {
		t.Fatalf("%+v", got)
	}
	toml := testfix.File(t, d, "config.toml", `
model = "x"
[mcp_servers.docs]
command = "node"
args = ["server.js"]
[mcp_servers.remote]
url = "https://example"
`)
	got = ReadMCP(toml)
	if len(got) != 1 || got[0].Name != "docs" || got[0].Command != "node" {
		t.Fatalf("toml %+v", got)
	}
}

func TestSitePackages(t *testing.T) {
	d := t.TempDir()
	testfix.Write(t, d, "_brotli.cpython-313-x86_64-linux-gnu.so", testfix.Spec{Table: true})
	testfix.File(t, d, "Brotli-1.2.0.dist-info/METADATA", "Name: Brotli\nVersion: 1.2.0\n")
	s := NewSet()
	s.SitePackages(d, "python "+d)
	subs := s.Subjects()
	if len(subs) != 1 || subs[0].PyVer != "1.2.0" || !strings.EqualFold(subs[0].PyDist, "brotli") {
		t.Fatalf("%+v", subs)
	}
}

func TestCodexAppRuntimes(t *testing.T) {
	home := t.TempDir()
	paths := []string{
		"AppData/Local/OpenAI/Codex/runtimes/cua_node/2b841c3d44b123ec/bin/node.exe",
		"AppData/Local/OpenAI/Codex/runtimes/cua_node/1fb7137c46617d50/bin/node.exe",
		"AppData/Local/OpenAI/Codex/bin/5b9024f90663758b/node.exe",
		".cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe",
	}
	for _, p := range paths {
		testfix.Write(t, home, p, testfix.Spec{Table: true})
	}
	s := NewSet()
	s.appGlobs(home)
	got := s.Subjects()
	if len(got) != len(paths) {
		t.Fatalf("found %d Codex runtimes, want %d: %+v", len(got), len(paths), got)
	}
	for _, sub := range got {
		if sub.Origin != "app" || !strings.HasPrefix(sub.Label, "Codex app") {
			t.Errorf("%s: label %q origin %q", sub.Real, sub.Label, sub.Origin)
		}
	}
}
