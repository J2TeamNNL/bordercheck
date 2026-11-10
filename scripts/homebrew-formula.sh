#!/bin/sh
# Renders the Homebrew formula for a release from its SHA256SUMS, on stdout.
# Usage: scripts/homebrew-formula.sh vX.Y.Z [path/to/SHA256SUMS] [owner/repo]
# Publish by committing the output as Formula/bordercheck.rb in the tap repo
# (github.com/ptrinh/homebrew-tap, installed as `brew install ptrinh/tap/bordercheck`).
set -eu
cd "$(dirname "$0")/.."
tag=${1:?usage: scripts/homebrew-formula.sh vX.Y.Z [SHA256SUMS] [owner/repo]}
sums=${2:-dist/SHA256SUMS}
repo=${3:-ptrinh/bordercheck}
case $tag in
v[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "homebrew-formula.sh: $tag is not a release tag (vX.Y.Z)" >&2; exit 1 ;;
esac

sha() {
	h=$(awk -v n="bordercheck-$tag-$1" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1 }' "$sums")
	case $h in
	[0-9a-f]*) [ ${#h} -eq 64 ] && { echo "$h"; return; } ;;
	esac
	echo "homebrew-formula.sh: no SHA-256 for bordercheck-$tag-$1 in $sums" >&2
	exit 1
}
da=$(sha darwin-arm64)
di=$(sha darwin-amd64)
la=$(sha linux-arm64)
li=$(sha linux-amd64)

sed -e "s|@TAG@|$tag|g" -e "s|@VERSION@|${tag#v}|g" -e "s|@REPO@|$repo|g" \
	-e "s|@SHA_DARWIN_ARM64@|$da|" -e "s|@SHA_DARWIN_AMD64@|$di|" \
	-e "s|@SHA_LINUX_ARM64@|$la|" -e "s|@SHA_LINUX_AMD64@|$li|" \
	packaging/homebrew/bordercheck.rb.tmpl
