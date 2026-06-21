import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from identity.store.server import ServerIdentityStore
from deploy.soak_provision import soak_provision
from deploy.soak_boot import SoakConfig, build_soak_app, assert_observation_isolated

ROUTE_MJS = Path(__file__).resolve().parents[2] / "cloud-hub" / "skills" / "capture-route" / "scripts" / "route.mjs"
SAMPLE_VAULT = Path(__file__).resolve().parent / "capture_bridge" / "fixtures" / "sample-vault"
FIXTURE_EVENT = json.loads((Path(__file__).resolve().parent / "capture_bridge" / "fixtures" / "telegram_text.json").read_text())


def test_observation_isolation_rejects_the_real_vault(tmp_path):
    real = tmp_path / "real-vault"
    with pytest.raises(RuntimeError):
        assert_observation_isolated(str(real), str(real))
    # a distinct path is fine
    assert_observation_isolated(str(tmp_path / "obs"), str(real))


def test_events_route_requires_a_jwt(tmp_path):
    cfg = _cfg(tmp_path)
    app, _, _ = build_soak_app(cfg, identity_db=str(tmp_path / "identity.sqlite"),
                               jwks_url="http://127.0.0.1:1/.well-known/jwks.json")
    client = TestClient(app)
    r = client.post("/events", json={"type": "x", "schema": "y", "source": "z",
                                     "trace": {"store": "s", "ref": "r"}, "data": {}})
    assert r.status_code == 401


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.skipif(not ROUTE_MJS.exists(), reason="capture-route not checked out alongside")
def test_published_event_routes_to_the_observation_vault(tmp_path):
    identity_db = str(tmp_path / "identity.sqlite")
    store = ServerIdentityStore(identity_db)
    soak_provision(store, principal_id="connector:telegram", org_id="org_caput",
                   now=time.time(), granted_by="prn_owner")
    cfg = _cfg(tmp_path)
    app, service, _ = build_soak_app(cfg, identity_db=identity_db,
                                     jwks_url="http://127.0.0.1:1/.well-known/jwks.json")
    # publish through the service directly (the HTTP path's only extra is JWT verification,
    # covered by the 401 test); this exercises stamp -> in-process delivery -> bridge.
    body = {
        "type": FIXTURE_EVENT["type"], "schema": FIXTURE_EVENT["schema"], "source": FIXTURE_EVENT["source"],
        "trace": FIXTURE_EVENT["trace"], "data": FIXTURE_EVENT["data"], "id": "evt_soak_1",
    }
    res = service.publish(body, principal="connector:telegram", org="org_caput")
    assert res["deduped"] is False

    inbox = Path(cfg.observation_vault) / "raw" / "inbox" / "2025-06-15.md"
    assert inbox.exists()
    assert "kom ihag" in inbox.read_text()
    log_lines = Path(cfg.soak_log).read_text().strip().splitlines()
    rec = json.loads(log_lines[-1])
    assert rec["eventId"] == "evt_soak_1"
    assert rec["type"] == "personal-task"
    assert rec["skipped"] is False


def _cfg(tmp_path) -> SoakConfig:
    return SoakConfig(
        issuer="http://127.0.0.1:1",
        audience="bus",
        observation_vault=str(tmp_path / "obs-vault"),
        real_vault=str(tmp_path / "real-vault"),
        soak_log=str(tmp_path / "soak.log"),
        route_mjs=str(ROUTE_MJS),
        claude_bin="claude",
        connector_principal="connector:telegram",
        org="org_caput",
        principal_map_entries=[{"channel": "telegram", "channelUserId": 111,
                                "principal": "prn_sam", "org": "org_caput"}],
        allowed_types=["work-task", "personal-task", "meal", "goal", "event",
                       "team-knowledge", "private-journal"],
        classify_type="personal-task",  # deterministic stub for the test; None in prod = real Claude CLI
    )
