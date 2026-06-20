import httpx

from tests.served_harness import build_served_kernel_stack, ACCESS_PATH


def test_three_services_boot_and_share_one_jwks(tmp_path):
    stack = build_served_kernel_stack(tmp_path)
    stack.start()
    try:
        jwks = httpx.get(f"{stack.identity_url}/.well-known/jwks.json", timeout=10).json()
        assert len(jwks["keys"]) == 1                 # one signing key
        assert jwks["keys"][0]["kid"] == "kid-kernel"
        # vault and bus are up and gated: no token -> 401
        assert httpx.post(f"{stack.vault_url}{ACCESS_PATH}", timeout=10).status_code == 401
        assert httpx.post(f"{stack.bus_url}/events", json={}, timeout=10).status_code == 401
    finally:
        stack.stop()
