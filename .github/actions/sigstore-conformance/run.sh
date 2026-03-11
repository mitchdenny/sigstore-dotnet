#!/usr/bin/env bash

set -euo pipefail

action_path="${GITHUB_WORKSPACE}/sigstore-conformance-action"

response="$(
  curl --silent --show-error --fail \
    -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore"
)"
identity_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])' <<<"${response}")"

echo "::add-mask::${identity_token}"

export GHA_SIGSTORE_CONFORMANCE_IDENTITY_TOKEN="${identity_token}"
export GITHUB_ACTION_PATH="${action_path}"

python3 - <<'PY'
from pathlib import Path

path = Path("sigstore-conformance-action/test/conftest.py")
text = path.read_text()
needle = '    MIN_VALIDITY = pytestconfig.getoption("--min-id-token-validity")\n'
injection = (
    '    env_token = os.getenv("GHA_SIGSTORE_CONFORMANCE_IDENTITY_TOKEN")\n'
    '    if env_token:\n'
    '        if _is_valid_at(env_token, datetime.now() + MIN_VALIDITY):\n'
    '            return env_token\n'
    '        print("Job OIDC token expires too early, falling back to beacon token.")\n'
    '\n'
)

if "GHA_SIGSTORE_CONFORMANCE_IDENTITY_TOKEN" not in text:
    if needle not in text:
        raise SystemExit("Failed to find MIN_VALIDITY assignment in sigstore-conformance conftest.py")

    text = text.replace(needle, needle + injection, 1)
    path.write_text(text)
PY

echo "::group::Install sigstore-conformance requirements"
# shellcheck disable=SC1090
source "${action_path}/setup/setup.bash"
echo "::endgroup::"

./sigstore-conformance-env/bin/python "${action_path}/action.py"
