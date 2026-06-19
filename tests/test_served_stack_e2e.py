import httpx

from tests.served_harness import build_served_stack, ACCESS_PATH


def _exchange(stack) -> str:
    r = httpx.post(f"{stack.identity_url}/auth/exchange",
                   json={"opaque_token": stack.cred, "audience": stack.audience}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def test_served_stack_fetches_token_over_http_without_refresh_token(tmp_path):
    stack = build_served_stack(tmp_path)
    stack.start()
    try:
        jwt = _exchange(stack)
        r = httpx.post(f"{stack.vault_url}{ACCESS_PATH}",
                       headers={"Authorization": f"Bearer {jwt}"}, timeout=10)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["accessToken"] == "FORTNOX_ACCESS"
        # the refresh token never leaves the vault
        assert "refreshToken" not in body and "refresh_token" not in body
    finally:
        stack.stop()


def test_served_stack_rejects_missing_bearer(tmp_path):
    stack = build_served_stack(tmp_path)
    stack.start()
    try:
        assert httpx.post(f"{stack.vault_url}{ACCESS_PATH}", timeout=10).status_code == 401
    finally:
        stack.stop()
