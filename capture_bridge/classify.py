"""Classify inbound text into the vault's routing vocabulary.

The allowed types are the manifest routing keys (one definition, supplied by the
caller) — not a hardcoded list. On any failure or an out-of-set answer, returns
"unclassifiable", which capture-route leaves parked in raw/inbox.
"""
import subprocess

UNCLASSIFIABLE = "unclassifiable"


def _default_runner(bin: str, prompt: str) -> str:
    proc = subprocess.run(
        [bin, "--print"], input=prompt, capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude cli: exit {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def _build_prompt(text: str, allowed_types: list[str]) -> str:
    options = " | ".join(allowed_types)
    return (
        "You classify a captured note into exactly one routing type.\n"
        "Output ONLY the single type string, nothing else — no prose, no quotes.\n"
        f"Allowed types: {options}\n\n"
        f"Note:\n{text}\n\n"
        "Respond with one type now."
    )


def classify(text: str, allowed_types: list[str], claude_bin: str, *, runner=None) -> str:
    run = runner or _default_runner
    try:
        raw = run(claude_bin, _build_prompt(text, allowed_types))
    except Exception:
        return UNCLASSIFIABLE
    answer = (raw or "").strip().splitlines()[0].strip() if raw and raw.strip() else ""
    return answer if answer in allowed_types else UNCLASSIFIABLE
