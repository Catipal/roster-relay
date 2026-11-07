#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Lay the phone app out as its own repository, from this tree's last commit:
#
#   mobile/tools/export-standalone.sh <folder>
#
# app/, core/, compat/ and tools/ come from mobile/; shared/ gets the node
# files the client compiles (mobile/standalone/shared-files.txt), unchanged;
# README, RELEASING, CHANGELOG and the workflows come from mobile/standalone/.
# Only committed files are taken, with Unix line endings. A .git folder already
# in <folder> is kept, so the export can be committed there as the next version.
set -euo pipefail

DEST=${1:?usage: export-standalone.sh <folder>}
TREE=$(cd "$(dirname "$0")/../.." && pwd)
STANDALONE=mobile/standalone
REPO_URL=https://github.com/Catipal/companion-app

if ! git -C "$TREE" diff-index --quiet HEAD -- mobile src COPYING configure.ac; then
    echo "note: uncommitted changes are not exported; this is HEAD" >&2
fi

mkdir -p "$DEST"
DEST=$(cd "$DEST" && pwd)
find "$DEST" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mapfile -t SHARED < <(git -C "$TREE" show "HEAD:$STANDALONE/shared-files.txt" | sed 's/\r$//' | grep -v '^#' | grep -v '^$')
git -C "$TREE" -c core.autocrlf=false archive HEAD mobile configure.ac "${SHARED[@]}" | tar -x -C "$TMP"

# The app and its client.
cp -r "$TMP/mobile/app" "$TMP/mobile/core" "$TMP/mobile/compat" "$DEST/"
mkdir -p "$DEST/tools" "$DEST/flatpak" "$DEST/fdroid" "$DEST/shared" "$DEST/.github/workflows"
cp "$TMP/mobile/tools/android.sh" "$DEST/tools/"

# The node's files, and the version lines the core reads in place of configure.ac.
for path in "${SHARED[@]}"; do
    mkdir -p "$DEST/shared/$(dirname "$path")"
    cp -r "$TMP/${path%/}" "$DEST/shared/$(dirname "$path")/"
done
grep -E '^define\(_(CLIENT_VERSION_(MAJOR|MINOR|REVISION|BUILD)|COPYRIGHT_YEAR), [0-9]+\)' "$TMP/configure.ac" > "$DEST/shared/version.ac"
printf '%s\n' "${SHARED[@]}" > "$DEST/shared/files.txt"
cp "$TMP/$STANDALONE/shared-README.md" "$DEST/shared/README.md"

# Packaging, with the paths of this layout.
sed -e 's#build mobile/flatpak/#build flatpak/#' \
    -e 's#subdir: mobile/app#subdir: app#' \
    -e 's#path: \.\./\.\.$#path: ..#' \
    -e '/^          - depends$/d' \
    -e 's#- mobile/flatpak/build#- flatpak/build#' \
    -e "s#<the project's repository>#$REPO_URL#" \
    "$TMP/mobile/flatpak/org.bps.companion.yml" > "$DEST/flatpak/org.bps.companion.yml"
sed -e 's#mobile/app/fastlane/#app/fastlane/#' \
    -e 's#subdir: mobile/app#subdir: app#' \
    -e 's#\.\./\.\./\.\./bps-mobile#../../bps-mobile#g' \
    -e "s#<the project's repository>#$REPO_URL#" \
    -e "s#<the project's issue tracker>#$REPO_URL/issues#" \
    -e 's#Not used by anything in this tree\.#Not used by the build itself.#' \
    "$TMP/mobile/fdroid/org.bps.companion.yml" > "$DEST/fdroid/org.bps.companion.yml"

# The repository's own pages and workflows.
cp "$TMP/$STANDALONE/README.md" "$TMP/$STANDALONE/RELEASING.md" "$TMP/$STANDALONE/CHANGELOG.md" "$DEST/"
cp "$TMP/$STANDALONE/gitignore" "$DEST/.gitignore"
cp "$TMP/$STANDALONE/workflows/"*.yml "$DEST/.github/workflows/"
cp "$TMP/COPYING" "$DEST/COPYING"
chmod +x "$DEST/tools/android.sh"

# The files rewritten for this layout must keep nothing of the BPS tree's.
# (core/ and tools/android.sh find their sources in either layout on purpose.)
if grep -rnE 'mobile/(app|core|compat|tools|flatpak|fdroid)|\.\./\.\./\.\./' \
       "$DEST/flatpak" "$DEST/fdroid" "$DEST/.github" "$DEST"/*.md; then
    echo "error: paths of the BPS tree left in the export (above)" >&2
    exit 1
fi
echo "exported HEAD ($(git -C "$TREE" rev-parse --short HEAD)) to $DEST: $(find "$DEST" -type f ! -path '*/.git/*' | wc -l) files"
