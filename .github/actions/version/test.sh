set -euo pipefail

ACTION_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

git init --bare --quiet "$TEST_ROOT/origin.git"
git init --quiet --initial-branch=main "$TEST_ROOT/work"
cd "$TEST_ROOT/work"
git config user.email "version-tests@example.invalid"
git config user.name "Version Tests"
echo "version tests" > README.md
git add README.md
git commit --quiet -m "Initial commit"
git remote add origin "$TEST_ROOT/origin.git"
git push --quiet --set-upstream origin main

SHORT_SHA="$(git rev-parse --short=7 HEAD)"

run_case() {
  local expected_kind="$1"
  local expected_base="$2"
  local expected_version="$3"
  local event_name="$4"
  local ref_name="$5"
  local base_ref="${6:-}"
  local release_flag="${7:-false}"
  local output
  output="$(mktemp "$TEST_ROOT/output.XXXXXX")"

  EVENT_NAME="$event_name" \
  REF_NAME="$ref_name" \
  BASE_REF="$base_ref" \
  PR_NUMBER=42 \
  RUN_NUMBER=12 \
  RUN_ATTEMPT=3 \
  GIT_SHA="$(git rev-parse HEAD)" \
  RELEASE_FLAG="$release_flag" \
  GITHUB_OUTPUT="$output" \
    bash "$ACTION_PATH/version.sh" >/dev/null

  grep -Fxq "kind=$expected_kind" "$output"
  grep -Fxq "base=$expected_base" "$output"
  grep -Fxq "version=$expected_version" "$output"
}

run_case alpha 1.0.0 "1.0.0-alpha.12.3.${SHORT_SHA}" push main

git tag v0.3.2
git tag v9.9.9-beta.1
git push --quiet origin --tags
git push --quiet origin HEAD:refs/heads/release/0.4

# The 0.x line is closed, so main opens at 1.0.0 regardless of how far 0.x progressed.
run_case alpha 1.0.0 "1.0.0-alpha.12.3.${SHORT_SHA}" push main
run_case pr 0.4.0 "0.4.0-pr.42.12.3.${SHORT_SHA}" pull_request ignored release/0.4
run_case beta 0.4.0 "0.4.0-beta.12.3.${SHORT_SHA}" push release/0.4

git tag v0.4.0
git tag v0.4.2
git push --quiet origin --tags

run_case beta 0.4.3 "0.4.3-beta.12.3.${SHORT_SHA}" push release/0.4
run_case release 0.4.3 0.4.3 workflow_dispatch release/0.4 "" true

# Cutting the first 1.x line: the branch itself opens at 1.0.0 and main advances past it.
run_case beta 1.0.0 "1.0.0-beta.12.3.${SHORT_SHA}" push release/1.0
git push --quiet origin HEAD:refs/heads/release/1.0
run_case alpha 1.1.0 "1.1.0-alpha.12.3.${SHORT_SHA}" push main
run_case release 1.0.0 1.0.0 workflow_dispatch release/1.0 "" true

# Once 1.0.0 ships, that line services patches while main stays on the next minor.
git tag v1.0.0
git push --quiet origin --tags
run_case beta 1.0.1 "1.0.1-beta.12.3.${SHORT_SHA}" push release/1.0
run_case alpha 1.1.0 "1.1.0-alpha.12.3.${SHORT_SHA}" push main

# A later minor moves main on without needing a release branch to exist first.
git tag v1.2.0
git push --quiet origin --tags
run_case alpha 1.3.0 "1.3.0-alpha.12.3.${SHORT_SHA}" push main

if EVENT_NAME=push REF_NAME=feature/test BASE_REF="" PR_NUMBER=42 RUN_NUMBER=12 RUN_ATTEMPT=3 \
  GIT_SHA="$(git rev-parse HEAD)" RELEASE_FLAG=false GITHUB_OUTPUT="$TEST_ROOT/unsupported.out" \
  bash "$ACTION_PATH/version.sh" >/dev/null 2>&1; then
  echo "Unsupported branches must fail."
  exit 1
fi

if EVENT_NAME=workflow_dispatch REF_NAME=main BASE_REF="" PR_NUMBER=42 RUN_NUMBER=12 RUN_ATTEMPT=3 \
  GIT_SHA="$(git rev-parse HEAD)" RELEASE_FLAG=true GITHUB_OUTPUT="$TEST_ROOT/main-release.out" \
  bash "$ACTION_PATH/version.sh" >/dev/null 2>&1; then
  echo "Stable releases from main must fail."
  exit 1
fi

echo "Version calculation tests passed."
