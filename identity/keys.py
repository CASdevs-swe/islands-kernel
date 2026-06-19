from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from identity.tokens import b64url, unb64url


class KeyManager:
    def __init__(self, kid: str, private_key: Ed25519PrivateKey) -> None:
        self.kid = kid
        self._priv = private_key

    @classmethod
    def generate(cls, kid: str) -> "KeyManager":
        return cls(kid, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, kid: str, seed_b64url: str) -> "KeyManager":
        return cls(kid, Ed25519PrivateKey.from_private_bytes(unb64url(seed_b64url)))

    def private_pem(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def _public_raw(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def public_jwk(self) -> dict:
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.kid,
            "x": b64url(self._public_raw()),
        }

    def jwks_document(self) -> dict:
        return {"keys": [self.public_jwk()]}
