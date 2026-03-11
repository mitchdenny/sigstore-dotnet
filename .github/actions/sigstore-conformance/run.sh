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
workflow_ref="${GITHUB_WORKFLOW_REF:-${GITHUB_REPOSITORY}/.github/workflows/build-deploy.yml@${GITHUB_REF}}"
export GHA_SIGSTORE_CONFORMANCE_CERTIFICATE_IDENTITY="https://github.com/${workflow_ref}"
export GITHUB_ACTION_PATH="${action_path}"

python3 - <<'PY'
from pathlib import Path

conftest_path = Path("sigstore-conformance-action/test/conftest.py")
text = conftest_path.read_text()
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
    conftest_path.write_text(text)

client_path = Path("sigstore-conformance-action/test/client.py")
client_text = client_path.read_text()
sign_snippet = '''        if getattr(materials, "signing_config", None) is not None:
            args.extend(["--signing-config", materials.signing_config])

        self.run(*args, artifact)
'''
sign_override = '''        if getattr(materials, "signing_config", None) is not None:
            args.extend(["--signing-config", materials.signing_config])

        materials.certificate_identity = os.getenv(
            "GHA_SIGSTORE_CONFORMANCE_CERTIFICATE_IDENTITY",
            CERTIFICATE_IDENTITY,
        )
        self.run(*args, artifact)
'''

verify_snippet = '''        else:
            args.extend(
                [
                    "--certificate-identity",
                    CERTIFICATE_IDENTITY,
                    "--certificate-oidc-issuer",
                    CERTIFICATE_OIDC_ISSUER,
                ]
            )
'''
verify_override = '''        else:
            expected_identity = getattr(materials, "certificate_identity", CERTIFICATE_IDENTITY)
            args.extend(
                [
                    "--certificate-identity",
                    expected_identity,
                    "--certificate-oidc-issuer",
                    CERTIFICATE_OIDC_ISSUER,
                ]
            )
'''

if "GHA_SIGSTORE_CONFORMANCE_CERTIFICATE_IDENTITY" not in client_text:
    if sign_snippet not in client_text:
        raise SystemExit("Failed to find sign path in sigstore-conformance client.py")
    if verify_snippet not in client_text:
        raise SystemExit("Failed to find verify path in sigstore-conformance client.py")

    client_text = client_text.replace(sign_snippet, sign_override, 1)
    client_text = client_text.replace(verify_snippet, verify_override, 1)
    client_path.write_text(client_text)
PY

echo "::group::Install sigstore-conformance requirements"
# shellcheck disable=SC1090
source "${action_path}/setup/setup.bash"
echo "::endgroup::"

./sigstore-conformance-env/bin/python "${action_path}/action.py"
