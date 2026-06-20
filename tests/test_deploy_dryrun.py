"""The deploy dry-run is the executable proof of the served-kernel recipe.

It boots identity + vault + bus as real uvicorn subprocesses from the template's
env var set and runs the kernel-integration smoke (one principal -> one JWT ->
vault access-token + bus event) with no VPS and no live Fortnox.
"""
from deploy.dryrun import run


def test_deploy_dryrun_smoke():
    result = run()
    assert result["event_accepted"] is True
    assert result["access_token_prefix"]
    # three distinct loopback ports were bound
    assert len(set(result["ports"])) == 3
