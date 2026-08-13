set -euo pipefail

# Resolves the stable release whose API becomes the new package validation baseline, and
# decides which branches should be offered a bump.
#
# A bump always targets release/X.Y so the next patch on that servicing line validates
# against the release that just shipped. It targets main only when X.Y is the highest minor
# of the highest released major, because main must not be pulled backwards to an older
# servicing line. When a release branch is later cut from main it inherits main's baseline,
# so no extra handling is needed here.

: "${EVENT_NAME:?EVENT_NAME is required}"
: "${RELEASE_TAG:=}"
: "${INPUT_VERSION:=}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

git fetch origin --tags --force --quiet

stable_tags() {
  git tag -l 'v*.*.*' \
    | sed -E 's@^v@@' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true
}

skip() {
  echo "::notice::$1"
  echo "skip=true" >> "$GITHUB_OUTPUT"
  exit 0
}

if [[ "$EVENT_NAME" == "release" ]]; then
  RAW="$RELEASE_TAG"
elif [[ -n "$INPUT_VERSION" ]]; then
  RAW="$INPUT_VERSION"
else
  RAW="$(stable_tags | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)"
  [[ -n "$RAW" ]] || skip "No stable tags exist; nothing to bump."
fi

VERSION="${RAW#v}"

if [[ ! "$VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  skip "'$RAW' is not a stable vX.Y.Z; skipping."
fi

MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"

# The released version is folded into the comparison so a line released right now still
# counts as the latest even if its tag is not visible locally.
HIGHEST_MAJOR="$( { stable_tags; echo "$VERSION"; } | awk -F. '{print $1}' | sort -n | tail -n1)"

HIGHEST_MINOR="$( {
  stable_tags | awk -F. -v major="$HIGHEST_MAJOR" '$1 == major {print $2}'
  if [[ "$MAJOR" == "$HIGHEST_MAJOR" ]]; then echo "$MINOR"; fi
} | sort -n | tail -n1)"

BUMP_MAIN=false
if [[ "$MAJOR" == "$HIGHEST_MAJOR" && "$MINOR" == "$HIGHEST_MINOR" ]]; then
  BUMP_MAIN=true
fi

{
  echo "skip=false"
  echo "version=$VERSION"
  echo "major=$MAJOR"
  echo "minor=$MINOR"
  echo "bump_main=$BUMP_MAIN"
} >> "$GITHUB_OUTPUT"

echo "Baseline version : $VERSION"
echo "Release branch   : release/${MAJOR}.${MINOR}"
echo "Bump main?       : $BUMP_MAIN"
