from src.common.hkdf import derive_session_key


def test_kdf_length():
    ss = b"\x01" * 32
    salt = b"\x02" * 16
    info = b"test"
    key = derive_session_key(ss, salt, info, length=32)
    assert isinstance(key, bytes)
    assert len(key) == 32
