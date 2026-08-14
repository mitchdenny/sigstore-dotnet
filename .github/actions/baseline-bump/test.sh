set -euo pipefail

# Exercises resolve.sh against synthetic tag histories and rewrite.sh against synthetic
# baseline files. bump.sh is not covered here because it talks to GitHub.

ACTION_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

FAILURES=0

fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

# ---------------------------------------------------------------------------
# resolve.sh
# ---------------------------------------------------------------------------

git init --bare --quiet "$TEST_ROOT/origin.git"
git init --quiet --initial-branch=main "$TEST_ROOT/work"
cd "$TEST_ROOT/work"
git config user.email "baseline-tests@example.invalid"
git config user.name "Baseline Tests"
echo "baseline tests" > README.md
git add README.md
git commit --quiet -m "Initial commit"
git remote add origin "$TEST_ROOT/origin.git"
git push --quiet --set-upstream origin main

tag() {
  git tag "$1"
  git push --quiet origin "$1"
}

resolve_case() {
  local description="$1" event_name="$2" release_tag="$3" input_version="$4"
  shift 4
  local output
  output="$(mktemp "$TEST_ROOT/output.XXXXXX")"

  EVENT_NAME="$event_name" \
  RELEASE_TAG="$release_tag" \
  INPUT_VERSION="$input_version" \
  GITHUB_OUTPUT="$output" \
    bash "$ACTION_PATH/resolve.sh" >/dev/null

  local expectation
  for expectation in "$@"; do
    grep -Fxq "$expectation" "$output" || fail "$description: expected '$expectation' in $(tr '\n' ' ' < "$output")"
  done
}

resolve_case "no tags at all" workflow_dispatch "" "" "skip=true"

tag v0.5.0

resolve_case "release event on the only line" release v0.5.0 "" \
  "skip=false" "version=0.5.0" "major=0" "minor=5" "bump_main=true"

resolve_case "dispatch falls back to the highest tag" workflow_dispatch "" "" \
  "skip=false" "version=0.5.0" "bump_main=true"

resolve_case "dispatch honours an explicit version" workflow_dispatch "" 0.5.0 \
  "skip=false" "version=0.5.0"

resolve_case "prerelease tags are ignored" release v0.6.0-dev "" "skip=true"
resolve_case "non-version tags are ignored" release nightly "" "skip=true"

tag v0.6.0

resolve_case "servicing an older minor leaves main alone" release v0.5.0 "" \
  "skip=false" "version=0.5.0" "minor=5" "bump_main=false"

resolve_case "the newest minor also bumps main" release v0.6.0 "" \
  "skip=false" "version=0.6.0" "minor=6" "bump_main=true"

tag v0.10.0

resolve_case "minors are compared numerically" release v0.10.0 "" \
  "skip=false" "version=0.10.0" "minor=10" "bump_main=true"

resolve_case "0.6.0 is not the newest once 0.10.0 exists" release v0.6.0 "" \
  "skip=false" "bump_main=false"

tag v1.0.0

resolve_case "a new major takes over main" release v1.0.0 "" \
  "skip=false" "version=1.0.0" "major=1" "minor=0" "bump_main=true"

resolve_case "the previous major no longer bumps main" release v0.10.0 "" \
  "skip=false" "bump_main=false"

resolve_case "a patch on the newest line bumps main" release v1.0.1 "" \
  "skip=false" "version=1.0.1" "bump_main=true"

# ---------------------------------------------------------------------------
# rewrite.sh
# ---------------------------------------------------------------------------

make_baseline_file() {
  cat > "$1" <<'EOF'
<Project>
  <PropertyGroup>
    <ExampleBefore>true</ExampleBefore>
    <!-- BEGIN: bot-managed baseline -->
    <PackageValidationBaselineVersion>0.4.0</PackageValidationBaselineVersion>
    <!-- END: bot-managed baseline -->
    <ExampleAfter>true</ExampleAfter>
  </PropertyGroup>
</Project>
EOF
}

BASELINE_A="$TEST_ROOT/A.props"
BASELINE_B="$TEST_ROOT/B.props"
make_baseline_file "$BASELINE_A"
make_baseline_file "$BASELINE_B"

PREVIOUS="$(VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh" "$BASELINE_A" "$BASELINE_B")"
[[ "$PREVIOUS" == "0.4.0" ]] || fail "rewrite reports the previous baseline (got '$PREVIOUS')"

grep -q '<PackageValidationBaselineVersion>0.5.0</PackageValidationBaselineVersion>' "$BASELINE_A" \
  || fail "rewrite pins the new version"
grep -q '<PackageValidationBaselineVersion>0.5.0</PackageValidationBaselineVersion>' "$BASELINE_B" \
  || fail "rewrite pins every file passed to it"
grep -q '<ExampleAfter>true</ExampleAfter>' "$BASELINE_A" \
  || fail "rewrite preserves content after the block"
grep -q '<ExampleBefore>true</ExampleBefore>' "$BASELINE_A" \
  || fail "rewrite preserves content before the block"
grep -q '^    <PackageValidationBaselineVersion>' "$BASELINE_A" \
  || fail "rewrite preserves the indentation of the block"
[[ "$(grep -c '<PackageValidationBaselineVersion>' "$BASELINE_A")" == "1" ]] \
  || fail "rewrite leaves exactly one baseline element"

cp "$BASELINE_A" "$TEST_ROOT/A.before"
VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh" "$BASELINE_A" >/dev/null
cmp -s "$BASELINE_A" "$TEST_ROOT/A.before" || fail "rewrite is idempotent"

# A block that lost its element still gets one back, so a hand-edited file recovers.
cat > "$TEST_ROOT/empty.props" <<'EOF'
<Project>
  <PropertyGroup>
    <!-- BEGIN: bot-managed baseline -->
    <!-- END: bot-managed baseline -->
  </PropertyGroup>
</Project>
EOF
PREVIOUS="$(VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh" "$TEST_ROOT/empty.props")"
[[ -z "$PREVIOUS" ]] || fail "rewrite reports no previous baseline for an empty block (got '$PREVIOUS')"
grep -q '<PackageValidationBaselineVersion>0.5.0</PackageValidationBaselineVersion>' "$TEST_ROOT/empty.props" \
  || fail "rewrite repopulates an empty block"

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$description"
  fi
}

cat > "$TEST_ROOT/nomarkers.props" <<'EOF'
<Project>
  <PropertyGroup />
</Project>
EOF
expect_failure "rewrite rejects a file without markers" \
  env VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh" "$TEST_ROOT/nomarkers.props"

expect_failure "rewrite rejects a missing file" \
  env VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh" "$TEST_ROOT/absent.props"

expect_failure "rewrite rejects a prerelease version" \
  env VERSION=0.5.0-beta.1 bash "$ACTION_PATH/rewrite.sh" "$BASELINE_A"

expect_failure "rewrite requires at least one file" \
  env VERSION=0.5.0 bash "$ACTION_PATH/rewrite.sh"

# A file that fails validation must be left untouched.
grep -q '<PackageValidationBaselineVersion>0.5.0</PackageValidationBaselineVersion>' "$BASELINE_A" \
  || fail "a rejected run leaves the file untouched"

if [[ "$FAILURES" -gt 0 ]]; then
  echo "$FAILURES baseline bump test(s) failed."
  exit 1
fi

echo "All baseline bump tests passed."
