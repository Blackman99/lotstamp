#!/bin/sh
# Downloads real runtimes and Debian Brotli packages into $1 (default ./dogfood) so the tests
# can check verdicts against the bytes people actually run. Nothing downloaded is executed.
set -eu
out="${1:-dogfood}"
mkdir -p "$out/deb"
cd "$out"
get() { curl -fsSL --retry 3 "$1" -o "$2"; }

for v in 20.19.5 24.22.0 24.22.1; do
  [ -d "node-v$v-linux-x64" ] && continue
  get "https://nodejs.org/dist/v$v/node-v$v-linux-x64.tar.xz" "node-v$v.tar.xz"
  tar -xJf "node-v$v.tar.xz" "node-v$v-linux-x64/bin/node"
done

for v in 1.4.3 1.4.4; do
  [ -d "bun-$v" ] && continue
  get "https://github.com/oven-sh/bun/releases/download/bun-v$v/bun-linux-x64.zip" "bun-$v.zip"
  mkdir -p "bun-$v" && (cd "bun-$v" && unzip -q "../bun-$v.zip")
done

# Debian 12: +b6 is the old build, +deb12u1 the DLA-4855-1 fix (Brotli 1.0.x stores bare error names).
for v in 1.0.9-2+b6 1.0.9-2+deb12u1; do
  d="deb/x-libbrotli1_$v"
  [ -d "$d" ] && continue
  f="libbrotli1_${v}_amd64.deb"
  ok=""
  for base in https://deb.debian.org/debian/pool/main/b/brotli \
              https://security.debian.org/debian-security/pool/updates/main/b/brotli \
              "https://snapshot.debian.org/archive/debian/20250101T000000Z/pool/main/b/brotli"; do
    if get "$base/$f" "deb/$f" 2>/dev/null; then ok=1; break; fi
  done
  [ -n "$ok" ] || { echo "could not download $f" >&2; exit 1; }
  mkdir -p "$d"
  (cd "$d" && ar x "../$f" && tar -xf data.tar.* ./usr/lib)
done
echo "real runtimes in $(pwd)"
