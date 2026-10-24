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
	for _, sub := range s.Subjects() {
		if sub.Real == target {
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
		"/home/u/.local/share/claude/versions/2.1.310":                                          "Claude Code 2.1.310",
		"/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe":                        "Claude Code (npm)",
		"/opt/VSCode-linux-x64/code":                                                            "VS Code",
		"/opt/VSCode-linux-x64/resources/app/node_modules.asar.unpacked/@vscode/vsce-sign/bin/vsce-sign": "VS Code · vsce-sign",
		"/opt/node-v24.22.0-linux-x64/bin/node":                                                 "node 24.22.0 tarball",
		"/usr/bin/somethingelse":                                                                "somethingelse",
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
