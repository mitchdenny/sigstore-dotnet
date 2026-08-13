set -euo pipefail

: "${EVENT_NAME:?EVENT_NAME is required}"
: "${REF_NAME:=}"
: "${BASE_REF:=}"
: "${PR_NUMBER:=}"
: "${RUN_NUMBER:?RUN_NUMBER is required}"
: "${RUN_ATTEMPT:?RUN_ATTEMPT is required}"
: "${GIT_SHA:?GIT_SHA is required}"
: "${RELEASE_FLAG:=false}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

git fetch origin --tags --force --quiet
git ls-remote origin HEAD >/dev/null

SHORT_SHA="${GIT_SHA:0:7}"

highest_release_branch_minor() {
  git ls-remote --heads origin 'refs/heads/release/*' \
    | awk '{print $2}' \
    | sed -E 's@^refs/heads/release/@@' \
    | grep -E '^[0-9]+\.[0-9]+$' \
    | sort -t. -k1,1n -k2,2n \
    | tail -n1 \
    | awk -F. '{print $1, $2}'
}

highest_tag_major() {
  git tag -l 'v*.*.*' \
    | sed -E 's@^v@@' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | awk -F. '{print $1}' \
    | sort -n \
    | tail -n1
}

highest_tag_minor_for_major() {
  local major="$1"
  git tag -l "v${major}.*.*" \
    | sed -E "s@^v${major}\\.@@" \
    | grep -E '^[0-9]+\.[0-9]+$' \
    | awk -F. '{print $1}' \
    | sort -n \
    | tail -n1
}

highest_tag_patch_for() {
  local major="$1" minor="$2"
  git tag -l "v${major}.${minor}.*" \
    | sed -E "s@^v${major}\\.${minor}\\.@@" \
    | grep -E '^[0-9]+$' \
    | sort -n \
    | tail -n1
}

if [[ "$EVENT_NAME" == "pull_request" ]]; then
  TARGET="$BASE_REF"
else
  TARGET="$REF_NAME"
fi

if [[ "$TARGET" == "main" ]]; then
  MAJOR="$(highest_tag_major || true)"
  MAJOR="${MAJOR:-0}"
  BRANCH_INFO="$(highest_release_branch_minor || true)"
  BRANCH_MAJOR=""
  BRANCH_MINOR=""
  if [[ -n "$BRANCH_INFO" ]]; then
    BRANCH_MAJOR="${BRANCH_INFO%% *}"
    BRANCH_MINOR="${BRANCH_INFO##* }"
  fi

  if [[ -n "$BRANCH_MAJOR" && "$BRANCH_MAJOR" -gt "$MAJOR" ]]; then
    MAJOR="$BRANCH_MAJOR"
  fi

  HIGHEST_MINOR=0
  TAG_MINOR="$(highest_tag_minor_for_major "$MAJOR" || true)"
  if [[ -n "$TAG_MINOR" && "$TAG_MINOR" -gt "$HIGHEST_MINOR" ]]; then
    HIGHEST_MINOR="$TAG_MINOR"
  fi
  if [[ -n "$BRANCH_MINOR" && "$BRANCH_MAJOR" == "$MAJOR" && "$BRANCH_MINOR" -gt "$HIGHEST_MINOR" ]]; then
    HIGHEST_MINOR="$BRANCH_MINOR"
  fi

  BASE="${MAJOR}.$((HIGHEST_MINOR + 1)).0"
  BRANCH_KIND="alpha"
elif [[ "$TARGET" =~ ^release/([0-9]+)\.([0-9]+)$ ]]; then
  MAJOR="${BASH_REMATCH[1]}"
  MINOR="${BASH_REMATCH[2]}"
  LAST_PATCH="$(highest_tag_patch_for "$MAJOR" "$MINOR" || true)"
  if [[ -z "$LAST_PATCH" ]]; then
    PATCH=0
  else
    PATCH=$((LAST_PATCH + 1))
  fi
  BASE="${MAJOR}.${MINOR}.${PATCH}"
  BRANCH_KIND="beta"
else
  echo "::error::Unsupported branch '$TARGET'. Use main or release/X.Y."
  exit 1
fi

case "$EVENT_NAME" in
  pull_request)
    KIND="pr"
    VERSION="${BASE}-pr.${PR_NUMBER}.${RUN_NUMBER}.${RUN_ATTEMPT}.${SHORT_SHA}"
    ;;
  push)
    KIND="$BRANCH_KIND"
    VERSION="${BASE}-${KIND}.${RUN_NUMBER}.${RUN_ATTEMPT}.${SHORT_SHA}"
    ;;
  workflow_dispatch)
    if [[ "$RELEASE_FLAG" == "true" ]]; then
      if [[ "$BRANCH_KIND" != "beta" ]]; then
        echo "::error::Final releases can only be dispatched from release/X.Y."
        exit 1
      fi
      KIND="release"
      VERSION="$BASE"
    else
      KIND="$BRANCH_KIND"
      VERSION="${BASE}-${KIND}.${RUN_NUMBER}.${RUN_ATTEMPT}.${SHORT_SHA}"
    fi
    ;;
  *)
    echo "::error::Unsupported event '$EVENT_NAME'."
    exit 1
    ;;
esac

echo "Target branch: $TARGET"
echo "Version kind: $KIND"
echo "Base version: $BASE"
echo "Build version: $VERSION"

{
  echo "kind=$KIND"
  echo "base=$BASE"
  echo "version=$VERSION"
} >> "$GITHUB_OUTPUT"
