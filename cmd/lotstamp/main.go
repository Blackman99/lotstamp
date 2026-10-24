// lotstamp reads the Brotli decoder that every runtime and AI tool on a machine carries and says
// whether it has the Node2Shell fix (CVE-2026-111497), without executing anything.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Blackman99/lotstamp/internal/advisory"
	"github.com/Blackman99/lotstamp/internal/discover"
	"github.com/Blackman99/lotstamp/internal/pkgdb"
	"github.com/Blackman99/lotstamp/internal/report"
	"github.com/Blackman99/lotstamp/internal/scan"
	"github.com/Blackman99/lotstamp/internal/verdict"
)

var version = "0.1.0"

const usage = `lotstamp — read the lot stamp on the Brotli decoder inside every runtime, without running it

usage:
  lotstamp [flags]            scan this machine: PATH (and launcher scripts), nvm/volta/fnm/mise/asdf,
                              ~/.bun, AI coding tools, app bundles, Python Brotli modules, MCP configs
  lotstamp [flags] PATH...    scan only these files or directories (CI artifacts, extracted apps)
  lotstamp advisory           print what lotstamp checks and why
  lotstamp version

flags:
  --json             machine-readable report
  --all              also list files that carry no Brotli decoder
  --fail-on LEVEL    behind (default) | unknown | never
  --no-color         plain output (NO_COLOR is honoured too)

exit: 0 nothing behind · 3 a decoder is behind (or unknown, with --fail-on unknown) · 1 error · 64 usage
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lotstamp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "")
	all := fs.Bool("all", false, "")
	noColor := fs.Bool("no-color", false, "")
	failOn := fs.String("fail-on", "behind", "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	if err := fs.Parse(reorder(args)); err != nil {
		fmt.Fprintf(stderr, "lotstamp: %v\n\n%s", err, usage)
		return 64
	}
	if *help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if *failOn != "behind" && *failOn != "unknown" && *failOn != "never" {
		fmt.Fprintf(stderr, "lotstamp: --fail-on wants behind, unknown or never (got %q)\n", *failOn)
		return 64
	}
	a := advisory.Load()
	rest := fs.Args()
	if len(rest) == 1 {
		switch rest[0] {
		case "version", "--version":
			fmt.Fprintf(stdout, "lotstamp %s (%s)\n", version, a.ID)
			return 0
		case "advisory":
			printAdvisory(stdout, a)
			return 0
		}
	}

	home, _ := os.UserHomeDir()
	set := discover.NewSet()
	scope := "this machine"
	if len(rest) > 0 {
		set.Paths(rest)
		scope = strings.Join(rest, ", ")
	} else {
		set.Machine(home)
	}
	start := time.Now()
	res := scan.Run(a, set.Subjects(), pkgdb.ReadOS())
	took := time.Since(start)

	if *jsonOut {
		if err := report.JSON(stdout, version, a, res, scope, *all, set.Notes); err != nil {
			fmt.Fprintf(stderr, "lotstamp: %v\n", err)
			return 1
		}
	} else {
		report.Text(stdout, a, res, report.Style{Color: report.UseColor(*noColor), All: *all, Home: home}, scope, took, set.Notes)
	}
	if len(rest) > 0 && res.Scanned == 0 && len(set.Notes) > 0 && len(set.Subjects()) == 0 {
		return 1
	}
	return exitCode(res, *failOn)
}

func exitCode(r scan.Result, failOn string) int {
	if failOn == "never" {
		return 0
	}
	for _, f := range r.Findings {
		if f.Status == verdict.Behind || f.Status == verdict.NoFixLine {
			return 3
		}
		if failOn == "unknown" && f.Status == verdict.Unknown {
			return 3
		}
	}
	return 0
}

// reorder lets flags come after paths: lotstamp dist/ --json.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if (a == "--fail-on" || a == "-fail-on") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func printAdvisory(w io.Writer, a *advisory.Advisory) {
	fmt.Fprintf(w, "%s (%s), published %s\n%s\n\n", a.ID, strings.Join(a.Names, ", "), a.Published, a.Title)
	fmt.Fprintf(w, "How lotstamp tells fixed from vulnerable code\n  %s\n  A decoder counts as present when at least %d of its %d known error names are in the file.\n\n", a.FixMarkerWhy, a.MinDecoder, len(a.DecoderNames))
	fmt.Fprintf(w, "Fixed releases\n  Brotli  %s\n  Node    %s (other lines get no fix)\n  Bun     %s\n  Electron  Chromium %d+ — %s\n", strings.Join(a.UpstreamFixed, ", "), a.Node.Advice, a.Bun.Fixed, a.Electron.FixedChromiumMajor, a.Electron.Why)
	fmt.Fprintf(w, "  PyPI    brotli %s, brotlicffi %s\n", a.PyPI["brotli"], a.PyPI["brotlicffi"])
	for name, d := range a.Distros {
		fmt.Fprintf(w, "  %s  %s:", name, d.Package)
		for c, v := range d.Fixed {
			fmt.Fprintf(w, " %s %s (%s);", c, v, d.Advisories[c])
		}
		fmt.Fprintf(w, " unfixed: %s\n          %s\n", strings.Join(d.Unfixed, ", "), d.Note)
	}
	fmt.Fprintf(w, "\nSources\n")
	for _, l := range a.Links {
		fmt.Fprintf(w, "  %s\n", l)
	}
}
