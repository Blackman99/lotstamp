package verdict

import "testing"

func TestFixCommands(t *testing.T) {
	for p, want := range map[string]string{
		"/home/a/.nvm/versions/node/v24.22.0/bin/node":                          "nvm install 24 && nvm alias default 24",
		"/home/a/.volta/tools/image/node/24.22.0/bin/node":                      "volta install node@24",
		"/home/a/.local/share/fnm/node-versions/v24.22.0/installation/bin/node": "fnm install 24 && fnm default 24",
		"/home/a/.local/share/mise/installs/node/24.22.0/bin/node":              "mise use -g node@24.22.1",
		"/opt/homebrew/Cellar/node/24.22.0/bin/node":                            "brew upgrade node",
		"/usr/local/bin/node": "",
	} {
		if got := nodeManagerFix(p, 24, "24.22.1"); got != want {
			t.Errorf("%s: got %q want %q", p, got, want)
		}
	}
	for p, want := range map[string]string{
		"/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe": "@anthropic-ai/claude-code",
		"/home/a/.local/lib/node_modules/bun/bin/bun.exe":                "bun",
		"/usr/local/lib/pnpm/5/.pnpm/bun@1.4.2/node_modules/bun/bin/bun": "",
		"/opt/app/bin/x": "",
	} {
		if got := npmGlobalPkg(p); got != want {
			t.Errorf("%s: got %q want %q", p, got, want)
		}
	}
	if got := pythonFor("/home/a/.local/lib/python3.13/site-packages/_brotli.so"); got != "python3.13 -m pip install --user" {
		t.Errorf("user site: %q", got)
	}
}
