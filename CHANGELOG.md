# Changelog

## Unreleased

- Discovery: the Codex desktop app's Windows Node runtimes (`%LOCALAPPDATA%\OpenAI\Codex\bin\<id>\node.exe`, `runtimes\cua_node\<id>\bin\node.exe`, `~/.cache/codex-runtimes/*/dependencies/node/bin/node.exe`) are now found and labelled, including old runtime folders that keep running until the app restarts. Paths come from reports in [openai/codex#56076](https://github.com/openai/codex/issues/56076); not yet run on a real Windows machine.

## v0.1.0 (2026-10-24)

First release. Reads the Brotli decoder in Node, Bun, Electron apps, Python brotli modules and system libbrotlidec (ELF, Mach-O, PE) and grades it for CVE-2026-111497 by the BLOCK_SWITCH fix marker, without executing anything. Verdicts FIXED / BEHIND / NO-FIX-LINE / UNKNOWN with fix commands for nvm, volta, fnm, mise, asdf, n, brew, npm/pnpm globals, Bun and pip. `--json`, `--json-file`, `--fail-on`, GitHub Action `Blackman99/lotstamp@v0`.
