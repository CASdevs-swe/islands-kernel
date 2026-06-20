"""Invoke Loom's capture-route CLI as a subprocess.

capture-route is a fixed substrate (cloud-hub). We call its CLI exactly as
documented: `node route.mjs '<json>'`, JSON in argv[2], JSON plan on stdout.
"""
import json
import subprocess


def call_capture_route(payload: dict, route_mjs: str, *, node_bin: str = "node") -> dict:
    proc = subprocess.run(
        [node_bin, route_mjs, json.dumps(payload)],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"capture-route: exit {proc.returncode}: {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"capture-route: unparseable stdout: {proc.stdout[:200]}") from e
