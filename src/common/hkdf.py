from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_session_key(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a symmetric session key from the PQC shared secret.
    length=32 -> AES-256 key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)
