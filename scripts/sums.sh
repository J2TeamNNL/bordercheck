#!/bin/sh
# Writes dist/SHA256SUMS for the release binaries in dist/ and signs it into
# dist/SHA256SUMS.sig when $BORDERCHECK_SIGNING_KEY is set (required for
# releases: installed copies only update to signed releases, and the install
# scripts refuse an unsigned one). Run it after anything that changes the
# binaries, such as macOS code signing.
set -eu
cd "$(dirname "$0")/../dist"
rm -f SHA256SUMS SHA256SUMS.sig
set -- bordercheck-*
[ -e "$1" ] || { echo "sums.sh: no bordercheck-* binaries in dist/" >&2; exit 1; }
if command -v sha256sum >/dev/null; then sha256sum -- "$@" >SHA256SUMS.tmp; else shasum -a 256 -- "$@" >SHA256SUMS.tmp; fi
mv SHA256SUMS.tmp SHA256SUMS
cd ..
if [ -n "${BORDERCHECK_SIGNING_KEY:-}" ]; then go run ./scripts/sign dist/SHA256SUMS; fi
