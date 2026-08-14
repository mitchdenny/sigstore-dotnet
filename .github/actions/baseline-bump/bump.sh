set -euo pipefail

# Opens (or updates) a pull request that bumps the package validation baseline on BRANCH to
# VERSION. Idempotent: if BRANCH already pins VERSION the script exits without touching git
# or the pull request.
#
# Inputs:
#   $1 BRANCH  - the base branch to target (e.g. main, release/0.5)
#   $2 VERSION - the stable X.Y.Z to pin as the baseline
#
# Requires the gh CLI authenticated with pull-request write access.

BRANCH="${1:?branch required}"
VERSION="${2:?version required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_FILE=PackageValidationBaseline.props

if ! git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  echo "::notice::Branch '$BRANCH' does not exist on origin; skipping."
  exit 0
fi

WORKTREE="$(mktemp -d)"
cleanup() {
  git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$WORKTREE"
}
trap cleanup EXIT

git fetch origin "$BRANCH" --quiet
git worktree add --detach "$WORKTREE" "origin/$BRANCH" >/dev/null

pushd "$WORKTREE" >/dev/null

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "::notice::$BASELINE_FILE is not present on $BRANCH; skipping."
  popd >/dev/null
  exit 0
fi

PREVIOUS="$(VERSION="$VERSION" bash "$SCRIPT_DIR/rewrite.sh" "$BASELINE_FILE")"

if git diff --quiet -- "$BASELINE_FILE"; then
  echo "Baseline on $BRANCH is already $VERSION; nothing to do."
  popd >/dev/null
  exit 0
fi

# Reuse the head branch of an open bump pull request so it is updated in place, otherwise
# mint a version-suffixed head branch so a previously merged or closed bump is not disturbed.
BRANCH_SLUG="${BRANCH//\//-}"

EXISTING_HEAD="$(gh pr list \
  --base "$BRANCH" \
  --state open \
  --json headRefName \
  --jq "[.[] | select(.headRefName | startswith(\"bot/baseline-bump/${BRANCH_SLUG}\"))][0].headRefName // empty" \
  2>/dev/null || true)"

if [[ -n "$EXISTING_HEAD" ]]; then
  HEAD_BRANCH="$EXISTING_HEAD"
  echo "Reusing open bump pull request head '$HEAD_BRANCH'."
else
  HEAD_BRANCH="bot/baseline-bump/${BRANCH_SLUG}-to-${VERSION}"
fi

git checkout -B "$HEAD_BRANCH" --quiet
git add "$BASELINE_FILE"
git commit --quiet -m "ci: pin package validation baseline to $VERSION on $BRANCH"
git push --force-with-lease --quiet origin "$HEAD_BRANCH"

TITLE="Pin package validation baseline to $VERSION on $BRANCH"
BODY="$(cat <<EOF
Pins \`<PackageValidationBaselineVersion>\` in \`PackageValidationBaseline.props\` to
**$VERSION**, following the stable release on \`$BRANCH\`.

- Previous baseline: \`${PREVIOUS:-none}\`
- New baseline: \`$VERSION\`

Once merged, every build on \`$BRANCH\` compares the public API against the $VERSION packages
on NuGet.org and fails on an undeclared breaking change. See
\`.github/workflows/baseline-bump.yml\` for when this pull request is raised.
EOF
)"

if [[ -n "$EXISTING_HEAD" ]]; then
  gh pr edit "$HEAD_BRANCH" --title "$TITLE" --body "$BODY"
else
  gh pr create --base "$BRANCH" --head "$HEAD_BRANCH" --title "$TITLE" --body "$BODY"
fi

popd >/dev/null
