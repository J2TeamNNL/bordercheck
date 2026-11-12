#!/bin/sh
# Maintainer only, on a Mac: builds the macOS binaries for a release from the
# tagged commit, signs them with a Developer ID and notarizes them here, where
# the signing key lives, and puts them in a draft GitHub release. It does the
# same for Bordercheck.app, the app bordercheck's macOS notifications come from
# (scripts/build-notifier.sh), which it also staples, and uploads as
# bordercheck-notifier-<tag>-darwin-universal.zip. Pushing the tag afterwards
# starts the release workflow, which takes these from the draft instead of
# building its own, checks them, writes and signs SHA256SUMS over everything,
# and publishes the release.
#
#   scripts/sign-macos-release.sh v1.2.3 [notes-file]
#
#   SIGN_ID         signing identity, e.g. "Developer ID Application: Sample Ltd (ABCDE12345)"
#   NOTARY_PROFILE  notarytool keychain profile (xcrun notarytool store-credentials)
#
# The workflow accepts the binaries only if they were built from exactly the
# tagged commit with a clean tree (and the app only if its Info.plist names
# that commit), so run this on that commit, before pushing the tag.
set -eu
cd "$(dirname "$0")/.."
tag=${1:?usage: scripts/sign-macos-release.sh vX.Y.Z [notes-file]}
notes=${2:-}
: "${SIGN_ID:?set SIGN_ID}" "${NOTARY_PROFILE:?set NOTARY_PROFILE}"

if [ -n "$(git status --porcelain)" ]; then
	echo "sign-macos-release: the working tree is not clean; commit or stash first" >&2
	exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null && [ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ]; then
	echo "sign-macos-release: $tag exists and is not this commit" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for arch in arm64 amd64; do
	out="$work/bordercheck-$tag-darwin-$arch"
	CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$tag" -o "$out" .
	codesign --force --sign "$SIGN_ID" --options runtime --timestamp --identifier io.github.ptrinh.bordercheck "$out"
	codesign --verify --strict --verbose=2 "$out"
	# A bare executable cannot be stapled; Gatekeeper looks the ticket up online.
	ditto -c -k --keepParent "$out" "$out.zip"
	xcrun notarytool submit "$out.zip" --keychain-profile "$NOTARY_PROFILE" --wait
	rm "$out.zip"
done
"$work/bordercheck-$tag-darwin-arm64" -version

# The notification app: built from this commit, signed (hardened runtime),
# notarized, stapled, checked as Gatekeeper would, then zipped for the release.
scripts/build-notifier.sh "$tag" --sign "$SIGN_ID"
app=build/notifier/Bordercheck.app
ditto -c -k --keepParent "$app" "$work/notarize-notifier.zip"
xcrun notarytool submit "$work/notarize-notifier.zip" --keychain-profile "$NOTARY_PROFILE" --wait
rm "$work/notarize-notifier.zip"
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
[ "$(/usr/libexec/PlistBuddy -c 'Print :BCSourceCommit' "$app/Contents/Info.plist")" = "$(git rev-parse HEAD)" ]
notifier_zip="$work/bordercheck-notifier-$tag-darwin-universal.zip"
ditto -c -k --norsrc --noextattr --keepParent "$app" "$notifier_zip"

if [ -n "$notes" ]; then set -- --notes-file "$notes"; else set -- --notes ""; fi
gh release create "$tag" --draft --title "$tag" --target "$(git rev-parse HEAD)" "$@" \
	"$work/bordercheck-$tag-darwin-arm64" "$work/bordercheck-$tag-darwin-amd64" "$notifier_zip"
echo "Draft release $tag holds the signed macOS binaries and notification app. Now: git tag $tag && git push origin $tag"
