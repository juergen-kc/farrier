#!/usr/bin/env bash
# Fills Packaging/homebrew/farrier.rb with a release's version and the zip's SHA-256.
#   scripts/render-cask.sh 0.1.0 <sha256> > farrier.rb
set -euo pipefail
VERSION=${1:?version}; SHA=${2:?sha256}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z" >&2; exit 2; }
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "sha256 must be 64 lowercase hex characters" >&2; exit 2; }
cd "$(dirname "$0")/.."
sed -e "s/^  version \".*\"/  version \"$VERSION\"/" \
    -e "s/^  sha256 :no_check/  sha256 \"$SHA\"/" \
    -e '/^# Homebrew cask for Farrier. TEMPLATE/,/^# the release workflow\.$/d' \
    Packaging/homebrew/farrier.rb
