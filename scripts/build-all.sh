#!/bin/sh
# Cross-compiles release binaries and SHA256SUMS into dist/.
# Usage: scripts/build-all.sh [version]
set -eu
cd "$(dirname "$0")/.."
version=${1:-dev}
rm -rf dist
mkdir -p dist
for target in darwin/arm64 darwin/amd64 windows/amd64 windows/arm64; do
	os=${target%/*}
	arch=${target#*/}
	ext=""
	[ "$os" = windows ] && ext=.exe
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" \
		-o "dist/bordercheck-$version-$os-$arch$ext" .
done
cd dist
if command -v sha256sum >/dev/null; then sha256sum -- * >../SHA256SUMS; else shasum -a 256 -- * >../SHA256SUMS; fi
mv ../SHA256SUMS .
ls -l
