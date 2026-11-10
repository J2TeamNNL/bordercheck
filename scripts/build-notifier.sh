#!/bin/sh
# Builds Bordercheck.app, the macOS app bordercheck posts its notifications
# through (universal: arm64 and x86_64), into build/notifier/. macOS only
# (swiftc, lipo, iconutil, codesign, ditto); no third-party tools.
#
# Usage: scripts/build-notifier.sh [version] [--sign IDENTITY] [--zip] [--test]
#   version          e.g. v1.2.3; goes in Info.plist (default: dev)
#   --sign IDENTITY  sign with this Developer ID Application identity, hardened
#                    runtime and secure timestamp ($KEYCHAIN, if set, is
#                    searched). Refuses a working tree with uncommitted changes.
#                    Without it the app is signed ad hoc: it runs, but
#                    bordercheck refuses to install it.
#   --zip            also write dist/bordercheck-notifier-<version>-darwin-universal.zip
#                    (scripts/sign-macos-release.sh zips again after stapling)
#   --test           build and run the contract tests instead (no app, no signing)
#
# Info.plist records the version, the commit (git rev-parse HEAD) and whether
# the tree was clean; the release workflow refuses an app not built from the
# tagged commit. The icon is drawn by macos/notifier/Icon/make-icon.swift.
#
# It never launches the app: running it could put macOS's notification question
# on the screen of whoever builds it.
set -eu
cd "$(dirname "$0")/.."
version=dev identity='' zip=no test=no
while [ $# -gt 0 ]; do
	case $1 in
	--sign) identity=${2:?--sign needs an identity}; shift 2 ;;
	--zip) zip=yes; shift ;;
	--test) test=yes; shift ;;
	-*) echo "unknown option $1" >&2; exit 2 ;;
	*) version=$1; shift ;;
	esac
done
printf '%s' "$version" | grep -Eq '^[A-Za-z0-9._-]+$' || { echo "bad version $version" >&2; exit 2; }
src=macos/notifier
out=build/notifier
rm -rf "$out"
mkdir -p "$out"

if [ "$test" = yes ]; then
	xcrun swiftc -swift-version 5 -o "$out/contract-tests" "$src/Sources/Request.swift" "$src/Tests/main.swift"
	"$out/contract-tests"
	exit 0
fi

commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
clean=true
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then clean=false; fi
if [ -n "$identity" ] && [ "$clean" != true ]; then
	echo "build-notifier: the working tree has uncommitted changes; a signed build must come from a commit" >&2
	exit 1
fi

# Info.plist versions are numbers only: v1.2.3-rc.1 -> 1.2.3; dev -> 0.0.0.
short_version=$(printf '%s' "$version" | sed -E 's/^v//; s/-.*$//')
printf '%s' "$short_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || short_version=0.0.0

app="$out/Bordercheck.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# The icon, drawn from code in the repository.
xcrun swiftc -O -swift-version 5 -o "$out/make-icon" "$src/Icon/make-icon.swift"
"$out/make-icon" "$out/AppIcon.iconset"
iconutil -c icns -o "$app/Contents/Resources/AppIcon.icns" "$out/AppIcon.iconset"

for arch in arm64 x86_64; do
	xcrun swiftc -O -swift-version 5 -target "$arch-apple-macos11.0" -o "$out/bordercheck-notifier-$arch" \
		"$src/Sources/Request.swift" "$src/Sources/main.swift"
done
lipo -create -output "$app/Contents/MacOS/bordercheck-notifier" "$out/bordercheck-notifier-arm64" "$out/bordercheck-notifier-x86_64"
rm -f "$out/bordercheck-notifier-arm64" "$out/bordercheck-notifier-x86_64"
sed -e "s/@SHORT_VERSION@/$short_version/g" -e "s/@VERSION@/$version/g" \
	-e "s/@COMMIT@/$commit/g" -e "s/@CLEAN@/$clean/g" "$src/Info.plist" >"$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null
printf 'APPL????' >"$app/Contents/PkgInfo"

# No entitlements: posting local notifications needs none.
if [ -n "$identity" ]; then
	set -- --sign "$identity" --timestamp
	[ -z "${KEYCHAIN:-}" ] || set -- "$@" --keychain "$KEYCHAIN"
else
	set -- --sign -
fi
codesign --force "$@" --options runtime --identifier io.github.ptrinh.bordercheck.notifier "$app"
codesign --verify --strict --deep --verbose=2 "$app"
codesign --display --verbose=2 "$app" 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier|Timestamp|Runtime|Format)' || true

if [ "$zip" = yes ]; then
	mkdir -p dist
	ditto -c -k --norsrc --noextattr --keepParent "$app" "dist/bordercheck-notifier-$version-darwin-universal.zip"
	ls -l "dist/bordercheck-notifier-$version-darwin-universal.zip"
fi
