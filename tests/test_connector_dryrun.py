# islands-kernel/tests/test_connector_dryrun.py
import shutil
from pathlib import Path

import pytest

from deploy.connector_dryrun import run

ROUTE_MJS = Path(__file__).resolve().parents[2] / "cloud-hub" / "skills" / "capture-route" / "scripts" / "route.mjs"
FIXTURE = Path(__file__).resolve().parent / "capture_bridge" / "fixtures" / "telegram_text.json"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.skipif(not ROUTE_MJS.exists(), reason="capture-route not checked out alongside")
def test_dryrun_routes_a_fixture_event_without_touching_real_destinations(tmp_path):
    vault = tmp_path / "vault"
    out = run(str(FIXTURE), str(vault), classify_type="personal-task", route_mjs=str(ROUTE_MJS))
    # the bus stamped a real principal/org and id onto the published event
    assert out["stamped"]["principal"] == "connector:telegram"
    assert out["stamped"]["org"] == "org_caput"
    assert out["stamped"]["id"]
    # the bridge produced a contained plan + write
    assert out["skipped"] is False
    assert out["plan"][0]["type"] == "personal-task"
    assert Path(out["inbox"]).exists()
    # content check: fixture text must appear in the written inbox file
    assert "kom ihag" in Path(out["inbox"]).read_text()
