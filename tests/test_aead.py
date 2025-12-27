from src.common.crypto_utils import aead_encrypt, aead_decrypt


def test_aead_roundtrip():
    key = b"\x00" * 32
    nonce = b"\x01" * 12
    aad = b"aad"
    pt = b"hello"
    ct = aead_encrypt(key, nonce, pt, aad)
    out = aead_decrypt(key, nonce, ct, aad)
    assert out == pt
