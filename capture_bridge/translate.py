"""Collapse a bus inbound event into capture-route's input envelope.

capture-route reads {startPath, today, thoughts:[{text, type, privacy}]} and,
per route.mjs, always appends every thought to raw/inbox before routing — so
startPath must point at a throwaway vault during soak (the bridge writes nowhere
real). privacy is currently unenforced by the engine; we still pass it so the
gate works once enforced.
"""


def translate(event: dict, *, type: str, privacy: str, vault_root: str, today: str) -> dict:
    text = event.get("data", {}).get("text", "")
    return {
        "startPath": vault_root,
        "today": today,
        "thoughts": [{"text": text, "type": type, "privacy": privacy}],
    }
