"""Resolve a channel-native sender to a kernel principal/org.

Built here, not inherited: the Telegram bot's allowlist is a bare set of numeric
ids with no principal/org mapping. A channel sender is never trusted as a kernel
principal on its own; only an explicit map entry grants identity.
"""


class PrincipalMap:
    def __init__(self, entries: list[dict]) -> None:
        # key on (channel, channelUserId)
        # Intentional asymmetry: construction fails fast on a malformed entry (bare dict access),
        # while resolve() soft-fails to None on an unknown sender.
        self._by_key = {
            (e["channel"], e["channelUserId"]): {"principal": e["principal"], "org": e["org"]}
            for e in entries
        }

    def resolve(self, sender: dict) -> dict | None:
        return self._by_key.get((sender.get("channel"), sender.get("channelUserId")))
