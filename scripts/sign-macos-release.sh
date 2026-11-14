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
#   NOTARY_PROFILE  notarytool keychain profile (xcrun notarytool store-credentials); only
#                   while the screen is unlocked. Or, for a locked screen too, an App Store
#                   Connect API key: NOTARY_KEY / NOTARY_KEY_ID / NOTARY_ISSUER, or ASC_KEY_PATH /
#                   ASC_KEY_ID / ASC_ISSUER_ID, e.g. after touchenv grant --for 2h ASC_KEY_PATH:
#     touchenv run --intent "release v1.2.3" ASC_KEY_PATH:file -- scripts/sign-macos-release.sh v1.2.3 notes.md
#
# With BORDERCHECK_SIGNING_KEY set (the release key, kept in touchenv: run the
# script under touchenv run --intent "release v1.2.3" BORDERCHECK_SIGNING_KEY
# ASC_KEY_PATH:file -- ...), it also builds the Linux and Windows binaries here,
# writes SHA256SUMS over every file and signs it, so the key never leaves this
# Mac; the workflow then only checks and publishes.
#
# The workflow accepts the binaries only if they were built from exactly the
# tagged commit with a clean tree (and the app only if its Info.plist names
# that commit), so run this on that commit, before pushing the tag.
set -eu
cd "$(dirname "$0")/.."
tag=${1:?usage: scripts/sign-macos-release.sh vX.Y.Z [notes-file]}
notes=${2:-}
: "${SIGN_ID:?set SIGN_ID}"

# notarize submits a zip and waits; it fails unless Apple accepted it. With
# NOTARY_PROFILE it signs in with that notarytool keychain profile, which only
# works while the screen is unlocked. Without it, with an App Store Connect API
# key: NOTARY_KEY (the .p8 file), NOTARY_KEY_ID and NOTARY_ISSUER, or else
# ASC_KEY_PATH, ASC_KEY_ID and ASC_ISSUER_ID. Run that way under touchenv
# (touchenv run --intent "release" ASC_KEY_PATH:file -- <this script> ...), after
# a touchenv grant for ASC_KEY_PATH, a release also goes through while the
# screen is locked.
notarize() {
	if [ -n "${NOTARY_PROFILE:-}" ]; then
		result=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1) || { echo "$result" >&2; return 1; }
	else
		key=${NOTARY_KEY:-${ASC_KEY_PATH:-}} key_id=${NOTARY_KEY_ID:-${ASC_KEY_ID:-}} issuer=${NOTARY_ISSUER:-${ASC_ISSUER_ID:-}}
		if [ -z "$key" ] || [ -z "$key_id" ] || [ -z "$issuer" ]; then
			echo "notarize: set NOTARY_PROFILE, or an App Store Connect API key (NOTARY_KEY, NOTARY_KEY_ID, NOTARY_ISSUER)" >&2
			return 1
		fi
		result=$(xcrun notarytool submit "$1" --key "$key" --key-id "$key_id" --issuer "$issuer" --wait 2>&1) || { echo "$result" >&2; return 1; }
	fi
	echo "$result"
	echo "$result" | grep -q "status: Accepted" || { echo "notarize: $1 was not accepted" >&2; return 1; }
}


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
	notarize "$out.zip"
	rm "$out.zip"
done
"$work/bordercheck-$tag-darwin-arm64" -version

# The notification app: built from this commit, signed (hardened runtime),
# notarized, stapled, checked as Gatekeeper would, then zipped for the release.
scripts/build-notifier.sh "$tag" --sign "$SIGN_ID"
app=build/notifier/Bordercheck.app
ditto -c -k --keepParent "$app" "$work/notarize-notifier.zip"
notarize "$work/notarize-notifier.zip"
rm "$work/notarize-notifier.zip"
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
[ "$(/usr/libexec/PlistBuddy -c 'Print :BCSourceCommit' "$app/Contents/Info.plist")" = "$(git rev-parse HEAD)" ]
notifier_zip="$work/bordercheck-notifier-$tag-darwin-universal.zip"
ditto -c -k --norsrc --noextattr --keepParent "$app" "$notifier_zip"

files="$work/bordercheck-$tag-darwin-arm64 $work/bordercheck-$tag-darwin-amd64 $notifier_zip"
if [ -n "${BORDERCHECK_SIGNING_KEY:-}" ]; then
	for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
		os=${target%/*} arch=${target#*/} ext=""
		[ "$os" = windows ] && ext=.exe
		out="$work/bordercheck-$tag-$os-$arch$ext"
		CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$tag" -o "$out" .
		files="$files $out"
	done
	(cd "$work" && shasum -a 256 -- bordercheck-* >SHA256SUMS)
	go run ./scripts/sign "$work/SHA256SUMS"
	# The key must be the one this commit's bordercheck trusts, or every installed copy would refuse the release.
	# shellcheck disable=SC2086
	go run . verify "$work/SHA256SUMS" "$work/SHA256SUMS.sig" $files
	files="$files $work/SHA256SUMS $work/SHA256SUMS.sig"
else
	echo "sign-macos-release: BORDERCHECK_SIGNING_KEY is not set; SHA256SUMS will be signed by the workflow (only up to v0.5.17)" >&2
fi

if [ -n "$notes" ]; then set -- --notes-file "$notes"; else set -- --notes ""; fi
# shellcheck disable=SC2086
gh release create "$tag" --draft --title "$tag" --target "$(git rev-parse HEAD)" "$@" $files
echo "Draft release $tag holds the signed binaries. Now: git tag $tag && git push origin $tag"
