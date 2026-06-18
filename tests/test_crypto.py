import nacl.utils
import pytest
from vault.model import Token
from vault.crypto import SecretboxKeyWrapper, seal_token, open_token, Envelope

def test_seal_open_roundtrip_secretbox():
    kek = nacl.utils.random(32)
    w = SecretboxKeyWrapper(kek)
    t = Token("acc", "ref", 123.0, "scope")
    blob = seal_token(t, w)
    assert open_token(blob, w) == t

def test_ciphertext_hides_plaintext():
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    blob = seal_token(Token("SECRETACCESS", "SECRETREFRESH", 1.0, "s"), w)
    assert b"SECRETACCESS" not in blob and b"SECRETREFRESH" not in blob

def test_wrong_kek_fails():
    t = Token("a", "r", 1.0, "s")
    blob = seal_token(t, SecretboxKeyWrapper(nacl.utils.random(32)))
    with pytest.raises(Exception):
        open_token(blob, SecretboxKeyWrapper(nacl.utils.random(32)))

def test_envelope_blob_roundtrip():
    e = Envelope(wrapped_dek=b"\x01\x02", nonce=b"\x03" * 24, ciphertext=b"\x04\x05\x06")
    assert Envelope.from_blob(e.to_blob()) == e

def test_age_wrapper_uses_injected_runner():
    from vault.crypto import AgeKeyWrapper
    calls = []

    def fake_runner(argv, stdin):
        calls.append(argv)
        if "-r" in argv:        # encrypt: return a fake ciphertext that embeds the dek
            return b"AGE[" + (stdin or b"") + b"]"
        return (stdin or b"")[4:-1]      # decrypt: strip the AGE[ ... ] wrapper

    w = AgeKeyWrapper(identity="ID", recipient="RCPT", runner=fake_runner)
    dek = b"k" * 32
    assert w.unwrap(w.wrap(dek)) == dek
    assert any("-r" in c for c in calls)
