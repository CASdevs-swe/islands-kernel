import shutil
from pathlib import Path

import pytest

from capture_bridge.route_caller import call_capture_route

ROUTE_MJS = Path(__file__).resolve().parents[2].parent / "cloud-hub" / "skills" / "capture-route" / "scripts" / "route.mjs"
FIXTURE_VAULT = Path(__file__).resolve().parent / "fixtures" / "sample-vault"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.skipif(not ROUTE_MJS.exists(), reason="capture-route not checked out alongside")
def test_routes_a_personal_task_and_writes_only_to_the_throwaway_vault(tmp_path):
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE_VAULT, vault)
    payload = {
        "startPath": str(vault), "today": "2025-06-15",
        "thoughts": [{"text": "kop mjolk", "type": "personal-task", "privacy": "private"}],
    }
    out = call_capture_route(payload, str(ROUTE_MJS))
    assert out["plan"][0]["type"] == "personal-task"
    assert out["plan"][0]["action"] == "delegate"
    # write was contained to the throwaway vault
    inbox = vault / "raw" / "inbox" / "2025-06-15.md"
    assert inbox.exists()
    assert "kop mjolk" in inbox.read_text()
