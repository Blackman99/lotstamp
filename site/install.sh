#!/bin/sh
# lotstamp installer: downloads the latest release binary for this machine,
# checks it against the release's checksums.txt, and puts it in ~/.local/bin
# (or $LOTSTAMP_BIN). Read it before you pipe it to sh; it is short.
set -eu

repo="Blackman99/lotstamp"
bin_dir="${LOTSTAMP_BIN:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) echo "lotstamp: no install.sh path for $os; download a binary from https://github.com/$repo/releases" >&2; exit 1 ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "lotstamp: no prebuilt binary for $arch; try: go install github.com/$repo/cmd/lotstamp@latest" >&2; exit 1 ;;
esac

if command -v curl >/dev/null 2>&1; then get() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then get() { wget -q "$1" -O "$2"; }
else echo "lotstamp: need curl or wget" >&2; exit 1; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
name="lotstamp_${os}_${arch}.tar.gz"
ver="${LOTSTAMP_VERSION:-latest}"
if [ "$ver" = latest ]; then base="https://github.com/$repo/releases/latest/download"
else base="https://github.com/$repo/releases/download/$ver"; fi
echo "lotstamp: downloading $name"
get "$base/$name" "$tmp/$name"
get "$base/checksums.txt" "$tmp/checksums.txt"

want=$(grep " $name\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$name" | cut -d' ' -f1)
else got=$(shasum -a 256 "$tmp/$name" | cut -d' ' -f1); fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "lotstamp: checksum mismatch for $name; nothing installed" >&2; exit 1
fi

tar -xzf "$tmp/$name" -C "$tmp" lotstamp
mkdir -p "$bin_dir"
mv "$tmp/lotstamp" "$bin_dir/lotstamp"
chmod 755 "$bin_dir/lotstamp"
echo "lotstamp: installed $("$bin_dir/lotstamp" version) to $bin_dir/lotstamp (sha256 ok)"
case ":$PATH:" in
  *":$bin_dir:"*) echo "next: lotstamp     (reads every runtime and AI tool here; executes nothing)" ;;
  *) echo "note: $bin_dir is not on your PATH; add it, or run $bin_dir/lotstamp" ;;
esac
