#!/bin/sh
# Cross-compiles release binaries into dist/, then writes and signs
# SHA256SUMS (scripts/sums.sh) unless --no-sums is given. The release workflow
# uses --no-sums so the macOS binaries can be code-signed first: a signature
# changes the file, so the checksums must come after it.
# Usage: scripts/build-all.sh [version] [--no-sums]
set -eu
cd "$(dirname "$0")/.."
version=dev
sums=yes
for arg in "$@"; do
	case $arg in
	--no-sums) sums=no ;;
	-*) echo "unknown option $arg" >&2; exit 2 ;;
	*) version=$arg ;;
	esac
done
rm -rf dist
mkdir -p dist
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
	os=${target%/*}
	arch=${target#*/}
	ext=""
	[ "$os" = windows ] && ext=.exe
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" \
		-o "dist/bordercheck-$version-$os-$arch$ext" .
done
if [ "$sums" = yes ]; then scripts/sums.sh; fi
ls -l dist
