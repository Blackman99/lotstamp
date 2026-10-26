# Changelog

## Unreleased

- Build: move from Go 1.22 (end of life; CI and the v0.1.0 binaries were built with go1.22.12) to Go 1.26, the oldest Go line that still gets security fixes. govulncheck reported three standard-library issues reachable from lotstamp under 1.22.12 (GO-2026-4602 in `os`, GO-2025-3956 in `os/exec` LookPath, GO-2025-3750 in `syscall` on Windows) and none under 1.26. CI now runs govulncheck on every push. `go install` needs Go 1.26 or newer.
- Discovery: the Codex desktop app's Windows Node runtimes (`%LOCALAPPDATA%\OpenAI\Codex\bin\<id>\node.exe`, `runtimes\cua_node\<id>\bin\node.exe`, `~/.cache/codex-runtimes/*/dependencies/node/bin/node.exe`) are now found and labelled, including old runtime folders that keep running until the app restarts. Paths come from reports in [openai/codex#56076](https://github.com/openai/codex/issues/56076); not yet run on a real Windows machine.

## v0.1.0 (2026-10-24)

First release. Reads the Brotli decoder in Node, Bun, Electron apps, Python brotli modules and system libbrotlidec (ELF, Mach-O, PE) and grades it for CVE-2026-111497 by the BLOCK_SWITCH fix marker, without executing anything. Verdicts FIXED / BEHIND / NO-FIX-LINE / UNKNOWN with fix commands for nvm, volta, fnm, mise, asdf, n, brew, npm/pnpm globals, Bun and pip. `--json`, `--json-file`, `--fail-on`, GitHub Action `Blackman99/lotstamp@v0`.
