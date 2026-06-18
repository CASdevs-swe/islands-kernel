from __future__ import annotations
import json
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Optional

import nacl.secret
import nacl.utils

from vault.model import Token

AgeRunner = Callable[[list[str], Optional[bytes]], bytes]


@dataclass
class Envelope:
    wrapped_dek: bytes
    nonce: bytes
    ciphertext: bytes

    def to_blob(self) -> bytes:
        parts = [self.wrapped_dek, self.nonce, self.ciphertext]
        return b"".join(struct.pack(">I", len(p)) + p for p in parts)

    @classmethod
    def from_blob(cls, blob: bytes) -> "Envelope":
        out, i = [], 0
        for _ in range(3):
            (n,) = struct.unpack(">I", blob[i:i + 4]); i += 4
            out.append(blob[i:i + n]); i += n
        return cls(*out)


class KeyWrapper(ABC):
    @abstractmethod
    def wrap(self, dek: bytes) -> bytes: ...
    @abstractmethod
    def unwrap(self, blob: bytes) -> bytes: ...


class SecretboxKeyWrapper(KeyWrapper):
    """Server backend: KEK-wraps the DEK with NaCl secretbox."""
    def __init__(self, kek: bytes):
        self._box = nacl.secret.SecretBox(kek)

    def wrap(self, dek: bytes) -> bytes:
        return bytes(self._box.encrypt(dek))

    def unwrap(self, blob: bytes) -> bytes:
        return bytes(self._box.decrypt(blob))


class AgeKeyWrapper(KeyWrapper):
    """Local backend: wraps the DEK via the `age` binary. Runner seam keeps it injectable in tests."""
    def __init__(self, identity: str, recipient: str, runner: AgeRunner):
        self._identity = identity
        self._recipient = recipient
        self._run = runner

    def wrap(self, dek: bytes) -> bytes:
        return self._run(["age", "-r", self._recipient, "-o", "-"], dek)

    def unwrap(self, blob: bytes) -> bytes:
        return self._run(["age", "-d", "-i", self._identity], blob)


def seal_token(
    token: Token,
    wrapper: KeyWrapper,
    gen_dek: Callable[[], bytes] = lambda: nacl.utils.random(32),
) -> bytes:
    dek = gen_dek()
    box = nacl.secret.SecretBox(dek)
    sealed = box.encrypt(json.dumps(token.to_dict()).encode())
    env = Envelope(wrapped_dek=wrapper.wrap(dek), nonce=sealed.nonce, ciphertext=sealed.ciphertext)
    return env.to_blob()


def open_token(blob: bytes, wrapper: KeyWrapper) -> Token:
    env = Envelope.from_blob(blob)
    dek = wrapper.unwrap(env.wrapped_dek)
    box = nacl.secret.SecretBox(dek)
    plain = box.decrypt(env.nonce + env.ciphertext)
    return Token.from_dict(json.loads(plain))
