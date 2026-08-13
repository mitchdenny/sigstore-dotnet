set -euo pipefail

# Rewrites the bot-managed <PackageValidationBaselineVersion> block in each project file
# passed as an argument, and prints the previous baseline of the first file that had one.
#
# Only the lines between the markers are touched, so hand-written package metadata around
# the block is preserved. Rewriting is idempotent: running it twice with the same version
# leaves the file byte-identical.

: "${VERSION:?VERSION is required}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::VERSION '$VERSION' is not a stable X.Y.Z." >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  echo "::error::At least one project file is required." >&2
  exit 1
fi

BEGIN_MARKER="<!-- BEGIN: bot-managed baseline -->"
END_MARKER="<!-- END: bot-managed baseline -->"

PREVIOUS=""

for project in "$@"; do
  if [[ ! -f "$project" ]]; then
    echo "::error::$project does not exist." >&2
    exit 1
  fi

  if ! grep -qF "$BEGIN_MARKER" "$project" || ! grep -qF "$END_MARKER" "$project"; then
    echo "::error::bot-managed baseline block not found in $project." >&2
    exit 1
  fi

  current="$(sed -n "/$(printf '%s' "$BEGIN_MARKER" | sed 's@[]\/$*.^[]@\\&@g')/,/$(printf '%s' "$END_MARKER" | sed 's@[]\/$*.^[]@\\&@g')/p" "$project" \
    | grep -oE '<PackageValidationBaselineVersion>[^<]+</PackageValidationBaselineVersion>' \
    | head -n1 \
    | sed -E 's@</?PackageValidationBaselineVersion>@@g' || true)"

  if [[ -z "$PREVIOUS" && -n "$current" ]]; then
    PREVIOUS="$current"
  fi

  rewritten="$(mktemp)"
  awk -v version="$VERSION" -v begin_marker="$BEGIN_MARKER" -v end_marker="$END_MARKER" '
    index($0, begin_marker) {
      match($0, /^[ \t]*/)
      indent = substr($0, 1, RLENGTH)
      print
      inside = 1
      next
    }
    inside && index($0, end_marker) {
      print indent "<PackageValidationBaselineVersion>" version "</PackageValidationBaselineVersion>"
      print
      inside = 0
      next
    }
    inside { next }
    { print }
  ' "$project" > "$rewritten"

  mv "$rewritten" "$project"
done

echo "$PREVIOUS"
