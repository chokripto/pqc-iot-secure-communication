import base64
import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def short_fingerprint(data: bytes, n: int = 10) -> str:
    """
    For demo-only logging: returns a short hash fingerprint, not the secret itself.
    """
    h = hashlib.sha256(data).hexdigest()
    return h[: 2 * n]


@dataclass
class NonceState:
    """
    AES-GCM requires a unique 12-byte nonce per key.
    We'll generate: nonce = prefix(4 bytes) + counter(8 bytes).
    """
    prefix4: bytes
    counter: int = 0

    def next_nonce(self) -> bytes:
        self.counter += 1
        return self.prefix4 + self.counter.to_bytes(8, "big")


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
