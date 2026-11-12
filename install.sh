#!/bin/sh
# Installs bordercheck on macOS or Linux and sets it up to report to your
# organisation every hour (a per-user service; no root, no sudo).
#
#   curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh \
#     | sh -s -- https://bordercheck.acme.com/policies.json
#
# or, with an invite link IT sent you (no email question; IT set it):
#
#   curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh \
#     | sh -s -- https://bordercheck.acme.com/i/<code>
#
# Options (after the URL or before it):
#   --email you@acme.com   don't ask for the work email (scripted rollouts; not with an invite link)
#   --version vX.Y.Z       install that release instead of the latest
#   --repo owner/name      install from a fork (with --key, the fork's release key); with an
#                          invite link, the installed copy also takes its updates from there
#   --key BASE64           the ed25519 public key that must sign SHA256SUMS
#   --dry-run              download and check, then stop before installing (never runs the download)
#
# What it checks before running anything it downloaded:
#   1. SHA256SUMS.sig is a valid ed25519 signature of SHA256SUMS by the key
#      below (with OpenSSL 3; otherwise see step 3),
#   2. the binary matches its line in SHA256SUMS,
#   3. without OpenSSL 3 (stock macOS), the signature is checked by the
#      downloaded binary itself (`bordercheck verify`) once step 2 passed.
# A dry run never executes the downloaded binary. Without capable OpenSSL it
# checks only the checksum and warns. Any mismatch stops the install. See docs/install.md, "What the install script proves".
#
# The whole script is one function called on the last line, so a download cut
# short runs nothing.

set -eu

# Keep equal to OfficialKey in internal/update/update.go (a test checks).
OFFICIAL_KEY='Q5Mw8yJQUgKSEtPNBVNnEP7HiSvhwT2y9Te4mEPOlcs='

# RFC 8032 test vector 2 (message 0x72, "r"), to learn whether this OpenSSL can
# verify ed25519 (OpenSSL refuses an empty message, so not vector 1).
PROBE_KEY='PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw='
PROBE_SIG='kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA=='

say() { printf '%s\n' "bordercheck-install: $*" >&2; }
die() {
	say "$*"
	say "Nothing was installed."
	exit 1
}

usage() {
	cat >&2 <<'EOF'
Usage: install.sh https://bordercheck.acme.com/policies.json [--email you@acme.com]
                  [--version vX.Y.Z] [--repo owner/name --key BASE64] [--dry-run]
       install.sh https://bordercheck.acme.com/i/<code>
                  [--version vX.Y.Z] [--repo owner/name --key BASE64] [--dry-run]
EOF
	exit 2
}

fetch() { # url file
	if command -v curl >/dev/null 2>&1; then
		if [ "$https_only" = yes ]; then
			curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' -o "$2" "$1"
		else
			curl -fsSL --retry 3 -o "$2" "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [ "$https_only" = yes ]; then
			wget -q --https-only -O "$2" "$1"
		else
			wget -q -O "$2" "$1"
		fi
	else
		die "neither curl nor wget is installed."
	fi
}

sha256() { # file -> lowercase hex
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
	else
		die "no sha256sum, shasum or openssl to check the download with."
	fi | tr 'A-F' 'a-f'
}

# der_key BASE64 FILE: an ed25519 public key as DER (SubjectPublicKeyInfo).
der_key() {
	{
		printf '\060\052\060\005\006\003\053\145\160\003\041\000'
		printf '%s' "$1" | openssl base64 -d -A
	} >"$2" 2>/dev/null
}

# openssl_ed25519_works: this OpenSSL verifies the RFC 8032 vector (OpenSSL 3
# does; LibreSSL on macOS and OpenSSL 1.1 do not).
openssl_ed25519_works() {
	command -v openssl >/dev/null 2>&1 || return 1
	der_key "$PROBE_KEY" "$tmp/probe.der" || return 1
	printf 'r' >"$tmp/probe.msg"
	printf '%s' "$PROBE_SIG" | openssl base64 -d -A >"$tmp/probe.sig" 2>/dev/null || return 1
	openssl pkeyutl -verify -pubin -inkey "$tmp/probe.der" -keyform DER -rawin \
		-in "$tmp/probe.msg" -sigfile "$tmp/probe.sig" >/dev/null 2>&1
}

main() {
	policy='' email='' version='' repo=${BORDERCHECK_REPO:-ptrinh/bordercheck}
	key=${BORDERCHECK_PUBLIC_KEY:-$OFFICIAL_KEY} dry_run=no
	# Whether the update source was named, by option or environment: an invite
	# install then pins it instead of the official one.
	repo_set=${BORDERCHECK_REPO:+yes} key_set=${BORDERCHECK_PUBLIC_KEY:+yes}
	github=${BORDERCHECK_GITHUB:-https://github.com} # tests point this at a local server
	while [ $# -gt 0 ]; do
		case $1 in
		--email | -email) email=${2:?--email needs a value}; shift 2 ;;
		--email=*) email=${1#*=}; shift ;;
		--version) version=${2:?--version needs a value}; shift 2 ;;
		--version=*) version=${1#*=}; shift ;;
		--repo) repo=${2:?--repo needs a value}; repo_set=yes; shift 2 ;;
		--repo=*) repo=${1#*=}; repo_set=yes; shift ;;
		--key) key=${2:?--key needs a value}; key_set=yes; shift 2 ;;
		--key=*) key=${1#*=}; key_set=yes; shift ;;
		--dry-run) dry_run=yes; shift ;;
		-h | --help) usage ;;
		-*) die "unknown option $1 (see --help)" ;;
		*)
			[ -z "$policy" ] || die "unexpected argument $1"
			policy=$1
			shift
			;;
		esac
	done
	policy=${policy:-${BORDERCHECK_POLICY_URL:-}}
	[ -n "$policy" ] || die "give your invite link or your organisation's policies URL, e.g.: sh -s -- https://bordercheck.acme.com/policies.json"
	case $policy in https://*) ;; *) die "the URL must start with https://" ;; esac
	# An invite link, https://<host>/i/<code>: keep in step with ParseInvite in internal/agent/enroll.go.
	invite=no
	if printf '%s' "$policy" | grep -Eq '^https://[^/?#@]+/i/[A-Za-z0-9._~-]+/?$'; then
		invite=yes
		[ -z "$email" ] || die "--email cannot be used with an invite link: IT set your email when they created the invite."
	fi
	printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "--repo must be owner/name"
	if [ -n "$version" ]; then
		printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' || die "--version must look like v1.2.3"
	fi
	https_only=no
	case $github in https://*) https_only=yes ;; esac

	case $(uname -s) in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) die "this script is for macOS and Linux; on Windows use install.ps1." ;;
	esac
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "no bordercheck build for $(uname -m)." ;;
	esac
	# A shell under Rosetta reports x86_64 on an Apple silicon Mac.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
		arch=arm64
	fi

	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t bordercheck)
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM

	releases=$github/$repo/releases
	if [ -n "$version" ]; then
		sums_base=$releases/download/$version
	else
		# Served by GitHub's CDN, not the rate-limited API, like the updater.
		sums_base=$releases/latest/download
	fi
	say "bordercheck · (c) Phil Trinh - SENPRINTS"
	say "Fetching the release list for $os/$arch from github.com/$repo ..."
	fetch "$sums_base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download SHA256SUMS from $sums_base"
	fetch "$sums_base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" ||
		die "the release has no SHA256SUMS.sig, so it cannot be verified."

	# 1. The signature, with OpenSSL when it can, before anything else is used.
	sig_checked=no
	if openssl_ed25519_works; then
		der_key "$key" "$tmp/key.der" && [ "$(wc -c <"$tmp/key.der" | tr -d ' ')" -eq 44 ] ||
			die "the release key is not a base64 ed25519 public key."
		tr -d '\r\n' <"$tmp/SHA256SUMS.sig" | openssl base64 -d -A >"$tmp/sig.bin" 2>/dev/null ||
			die "SHA256SUMS.sig is not base64."
		openssl pkeyutl -verify -pubin -inkey "$tmp/key.der" -keyform DER -rawin \
			-in "$tmp/SHA256SUMS" -sigfile "$tmp/sig.bin" >/dev/null 2>&1 ||
			die "SHA256SUMS is NOT signed by the bordercheck release key. Do not install this release; tell your IT team."
		sig_checked=yes
		say "SHA256SUMS is signed by the release key (checked with OpenSSL)."
	fi

	# The release's binary for this machine; its name carries the version.
	asset=$(awk -v os="$os" -v arch="$arch" '
		{ n = $2; sub(/^\*/, "", n) }
		n ~ ("^bordercheck-v[0-9][A-Za-z0-9.-]*-" os "-" arch "$") { print n; exit }' "$tmp/SHA256SUMS")
	[ -n "$asset" ] || die "the release has no binary for $os/$arch."
	want=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1; exit }' "$tmp/SHA256SUMS" | tr 'A-F' 'a-f')
	tag=${asset#bordercheck-}
	tag=${tag%-"$os"-"$arch"}
	if [ -n "$version" ] && [ "$tag" != "$version" ]; then
		die "SHA256SUMS of $version lists $asset."
	fi

	say "Downloading $asset ..."
	fetch "$releases/download/$tag/$asset" "$tmp/$asset" || die "could not download $asset"

	# 2. The checksum, before the binary runs.
	got=$(sha256 "$tmp/$asset")
	[ "${#want}" -eq 64 ] && [ "$got" = "$want" ] ||
		die "$asset does NOT match SHA256SUMS (expected $want, got $got). Do not install it; tell your IT team."
	say "$asset matches SHA256SUMS."

	set -- install "$policy"
	[ -z "$email" ] || set -- "$@" -email "$email"
	if [ "$invite" = yes ]; then
		[ "$repo_set" != yes ] || set -- "$@" -update-repo "$repo"
		[ "$key_set" != yes ] || set -- "$@" -update-key "$key"
	fi
	if [ "$dry_run" = yes ]; then
		if [ "$sig_checked" = no ]; then
			say "Note: OpenSSL 3 was not found, so only the checksum was checked; the release signature was not verified."
		fi
		say "Dry run ($tag): would now run: bordercheck $*"
		return 0
	fi
	chmod 755 "$tmp/$asset"

	# 3. Without OpenSSL 3, the binary checks the signature with the key this script pins.
	if [ "$sig_checked" = no ]; then
		"$tmp/$asset" verify -key "$key" "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.sig" "$tmp/$asset" >/dev/null ||
			die "SHA256SUMS is NOT signed by the bordercheck release key. Do not install this release; tell your IT team."
		say "SHA256SUMS is signed by the release key (checked by the downloaded binary; OpenSSL 3 was not found)."
	fi
	"$tmp/$asset" -version | grep -qF "$tag" || die "$asset does not report version $tag."

	if [ "$invite" = yes ]; then
		# Nothing to ask: the invite carries the email.
		"$tmp/$asset" "$@" </dev/null
	elif [ -n "$email" ]; then
		"$tmp/$asset" "$@" </dev/null
	elif (exec </dev/tty) 2>/dev/null; then
		# Piped into sh, stdin is this script: ask on the terminal instead.
		"$tmp/$asset" "$@" </dev/tty
	else
		die "there is no terminal to ask for your work email; pass --email you@acme.com."
	fi
}

main "$@"
