// Package report renders findings for terminals and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Blackman99/lotstamp/internal/advisory"
	"github.com/Blackman99/lotstamp/internal/scan"
	"github.com/Blackman99/lotstamp/internal/verdict"
)

type Style struct {
	Color bool
	All   bool
	Home  string
}

func (s Style) c(code, t string) string {
	if !s.Color {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}

func (s Style) tilde(p string) string {
	if s.Home != "" && strings.HasPrefix(p, s.Home+string(filepath.Separator)) {
		return "~" + p[len(s.Home):]
	}
	return p
}

func statusColor(st verdict.Status) string {
	switch st {
	case verdict.Fixed:
		return "32"
	case verdict.Behind:
		return "1;31"
	case verdict.NoFixLine:
		return "1;35"
	case verdict.Unknown:
		return "33"
	}
	return "2"
}

// Text writes the human report.
func Text(w io.Writer, a *advisory.Advisory, r scan.Result, s Style, scope string, took time.Duration, notes []string) {
	fmt.Fprintf(w, "%s  %s · %s (%s)\n", s.c("1", "lotstamp"), a.ID, strings.Join(a.Names, "/"), "Brotli decoder")
	fmt.Fprintf(w, "%s\n\n", s.c("2", fmt.Sprintf("read %d files in %s · %s · nothing was executed", r.Scanned, took.Round(10*time.Millisecond), scope)))

	counts := map[verdict.Status]int{}
	shown := 0
	for _, f := range r.Findings {
		counts[f.Status]++
		if f.Status == verdict.Absent && !s.All {
			continue
		}
		shown++
		writeFinding(w, f, s)
	}
	for _, n := range notes {
		fmt.Fprintf(w, "%s %s\n", s.c("33", "note"), n)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "%s %s\n", s.c("33", "skipped"), s.tilde(e))
	}
	if shown == 0 && len(notes) == 0 {
		fmt.Fprintf(w, "No Brotli decoder found in %s.\n", scope)
	}
	var parts []string
	for _, st := range []verdict.Status{verdict.NoFixLine, verdict.Behind, verdict.Unknown, verdict.Fixed} {
		if counts[st] > 0 {
			parts = append(parts, s.c(statusColor(st), fmt.Sprintf("%d %s", counts[st], strings.ToLower(string(st)))))
		}
	}
	if len(parts) > 0 {
		if shown == 0 || len(notes)+len(r.Errors) > 0 {
			fmt.Fprintln(w) // findings already end with a blank line
		}
		fmt.Fprintf(w, "%s decoders: %s", s.c("1", "total"), strings.Join(parts, " · "))
		if counts[verdict.Absent] > 0 && !s.All {
			fmt.Fprint(w, s.c("2", fmt.Sprintf("   (%s no decoder; --all lists them)", map[bool]string{true: "1 more file has", false: fmt.Sprintf("%d more files have", counts[verdict.Absent])}[counts[verdict.Absent] == 1])))
		}
		fmt.Fprintln(w)
	}
	if counts[verdict.Behind]+counts[verdict.NoFixLine] == 0 && counts[verdict.Fixed] > 0 {
		fmt.Fprintln(w, s.c("32", "Every decoder found carries the fix."))
	}
}

func writeFinding(w io.Writer, f verdict.Finding, s Style) {
	tag := fmt.Sprintf("%-11s", f.Status)
	fmt.Fprintf(w, "%s %s  %s\n", s.c(statusColor(f.Status), tag), s.c("1", f.Label), s.c("2", s.tilde(f.Path)))
	pad := strings.Repeat(" ", 12)
	if f.Runtime != "" {
		fmt.Fprintf(w, "%s%s\n", pad, f.Runtime)
	}
	fmt.Fprintf(w, "%sdecoder  %s\n", pad, f.Decoder)
	if f.Says != "" {
		fmt.Fprintf(w, "%s%s  %s\n", pad, s.c("36", "version"), f.Says)
		fmt.Fprintf(w, "%s%s  %s\n", pad, s.c("36", "    but"), f.But)
	}
	for _, v := range f.Via {
		if strings.HasSuffix(v, " (launcher script)") && stem(strings.TrimSuffix(strings.TrimPrefix(v, "PATH "), " (launcher script)")) != stem(f.Path) {
			continue // a script that merely mentions the runtime is not how you reach it
		}
		if strings.HasPrefix(v, "PATH ") || strings.HasPrefix(v, "MCP ") {
			fmt.Fprintf(w, "%s  found  %s\n", pad, s.tilde(strings.TrimPrefix(v, "PATH ")))
			break
		}
	}
	for _, u := range f.UsedBy {
		fmt.Fprintf(w, "%sused by  %s\n", pad, s.tilde(u))
	}
	for _, m := range f.MCP {
		fmt.Fprintf(w, "%s    MCP  %s\n", pad, m)
	}
	if f.Fix != "" {
		who := ""
		if f.Who != "" {
			who = s.c("2", "  · who: "+f.Who)
		}
		fmt.Fprintf(w, "%s    %s  %s%s\n", pad, s.c("1", "fix"), f.Fix, who)
	}
	fmt.Fprintln(w)
}

// JSONDoc is the --json output.
type JSONDoc struct {
	Tool      string            `json:"tool"`
	Version   string            `json:"version"`
	Advisory  string            `json:"advisory"`
	Scope     string            `json:"scope"`
	FilesRead int               `json:"files_read"`
	Counts    map[string]int    `json:"counts"`
	Findings  []verdict.Finding `json:"findings"`
	Errors    []string          `json:"errors,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
}

func JSON(w io.Writer, version string, a *advisory.Advisory, r scan.Result, scope string, all bool, notes []string) error {
	d := JSONDoc{Tool: "lotstamp", Version: version, Advisory: a.ID, Scope: scope, FilesRead: r.Scanned, Counts: map[string]int{}, Errors: r.Errors, Notes: notes}
	d.Findings = []verdict.Finding{}
	for _, f := range r.Findings {
		d.Counts[string(f.Status)]++
		if f.Status == verdict.Absent && !all {
			continue
		}
		d.Findings = append(d.Findings, f)
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(d)
}

// UseColor decides whether stdout gets ANSI colors.
func UseColor(flag bool) bool {
	if flag || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func stem(p string) string {
	b := filepath.Base(strings.ReplaceAll(p, `\`, "/"))
	if i := strings.IndexByte(b, '.'); i > 0 {
		b = b[:i]
	}
	return strings.ToLower(b)
}
