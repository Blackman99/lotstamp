package discover

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Blackman99/lotstamp/internal/verdict"
)

// MCPServer is one configured MCP server that runs as a local process.
type MCPServer struct {
	Name    string
	Command string
	Config  string
}

// MCPConfigs lists the config files lotstamp reads.
func MCPConfigs(home string) []string {
	return []string{
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, ".gemini", "settings.json"),
		".mcp.json", filepath.Join(".cursor", "mcp.json"), filepath.Join(".vscode", "mcp.json"),
	}
}

// ReadMCP returns the local (command-based) MCP servers in one config file.
func ReadMCP(path string) []MCPServer {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if strings.HasSuffix(path, ".toml") {
		return readCodexTOML(path, string(b))
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []MCPServer
	collect := func(m any, scope string) {
		servers, _ := m.(map[string]any)
		names := make([]string, 0, len(servers))
		for n := range servers {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			cfg, _ := servers[n].(map[string]any)
			cmd, _ := cfg["command"].(string)
			if cmd == "" {
				continue
			}
			name := n
			if scope != "" {
				name = n + " (" + scope + ")"
			}
			out = append(out, MCPServer{Name: name, Command: cmd, Config: path})
		}
	}
	collect(doc["mcpServers"], "")
	collect(doc["servers"], "")                               // .vscode/mcp.json
	if projects, ok := doc["projects"].(map[string]any); ok { // ~/.claude.json per-project servers
		keys := make([]string, 0, len(projects))
		for k := range projects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p, _ := projects[k].(map[string]any)
			collect(p["mcpServers"], filepath.Base(k))
		}
	}
	return out
}

func readCodexTOML(path, s string) []MCPServer {
	var out []MCPServer
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			cur = ""
			h := strings.Trim(line, "[] ")
			if strings.HasPrefix(h, "mcp_servers.") && !strings.Contains(strings.TrimPrefix(h, "mcp_servers."), ".") {
				cur = strings.Trim(strings.TrimPrefix(h, "mcp_servers."), `"`)
			}
			continue
		}
		if cur == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "command" {
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			out = append(out, MCPServer{Name: cur, Command: v, Config: path})
		}
	}
	return out
}

// runtimeFor maps an MCP launch command to the runtime binary that will run the server.
func runtimeFor(cmd string) string {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(cmd)), ".exe")
	want := ""
	switch base {
	case "npx", "npm", "node", "nodejs", "pnpm", "pnpx", "yarn", "tsx":
		want = "node"
	case "bun", "bunx":
		want = "bun"
	default:
		if filepath.IsAbs(cmd) {
			return cmd
		}
		if p, err := exec.LookPath(cmd); err == nil {
			return p
		}
		return ""
	}
	p, err := exec.LookPath(want)
	if err != nil {
		return ""
	}
	return p
}

func (s *Set) mcp(home string) {
	for _, c := range MCPConfigs(home) {
		for _, srv := range ReadMCP(c) {
			rt := runtimeFor(srv.Command)
			if rt == "" {
				continue
			}
			info, err := os.Stat(rt)
			if err != nil {
				continue
			}
			tag := srv.Name + " via " + srv.Command + " (" + tildify(srv.Config, home) + ")"
			var sub = s.lookup(rt)
			if sub == nil && Interesting(rt, info) {
				sub = s.Add(rt, originFor(rt, ""), "MCP config "+tildify(srv.Config, home))
			}
			if sub == nil {
				s.followShim(rt, nil)
				continue
			}
			if !contains(sub.MCP, tag) {
				sub.MCP = append(sub.MCP, tag)
			}
		}
	}
}

func (s *Set) lookup(p string) *verdict.Subject {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil
	}
	if abs, err := filepath.Abs(real); err == nil {
		real = abs
	}
	return s.byReal[real]
}

func tildify(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "~" + p[len(home):]
	}
	return p
}
