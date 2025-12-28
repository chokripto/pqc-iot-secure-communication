import os
import socket

from pqcrypto.kem import kyber512

from src.common.crypto_utils import b64e, b64d, NonceState, aead_encrypt, aead_decrypt, short_fingerprint
from src.common.hkdf import derive_session_key
from src.common.message import send_frame, recv_frame


HOST = "server"
PORT = 9000


def build_info(session_id: bytes) -> bytes:
    return b"pqc-iot-demo|" + session_id


def run_device() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"[device] Connected to {HOST}:{PORT}")

        # 1) Receive server_hello
        hello = recv_frame(s)
        if hello.get("type") != "server_hello":
            raise ValueError(f"Unexpected message type: {hello.get('type')}")

        pk = b64d(hello["pk_b64"])
        session_id = b64d(hello["session_id_b64"])
        salt = b64d(hello["salt_b64"])
        server_nonce_prefix = b64d(hello["server_nonce_prefix_b64"])

        # 2) Encapsulate to obtain (ct, shared_secret)
        ct, shared_secret = kyber512.encrypt(pk)
        info = build_info(session_id)
        session_key = derive_session_key(shared_secret, salt=salt, info=info, length=32)

        print(f"[device] Session parameters received.")
        print(f"[device] session_id(fp)={short_fingerprint(session_id)} salt(fp)={short_fingerprint(salt)}")
        print(f"[device] ss(fp)={short_fingerprint(shared_secret)} key(fp)={short_fingerprint(session_key)}")

        # Nonce prefixes
        client_nonce_prefix = os.urandom(4)

        # 3) Send client_kem with ciphertext + client nonce prefix
        send_frame(s, {
            "type": "client_kem",
            "ct_b64": b64e(ct),
            "client_nonce_prefix_b64": b64e(client_nonce_prefix),
        })

        # Prepare nonce states:
        send_state = NonceState(prefix4=client_nonce_prefix, counter=0)    # device -> server
        recv_state = NonceState(prefix4=server_nonce_prefix, counter=0)    # server -> device

        # 4) Receive encrypted session_ack
        ack = recv_frame(s)
        if ack.get("type") != "session_ack":
            raise ValueError(f"Unexpected message type: {ack.get('type')}")

        nonce_ack = b64d(ack["nonce_b64"])
        aad_ack = b64d(ack["aad_b64"])
        ct_ack = b64d(ack["ciphertext_b64"])

        expected_nonce_ack = recv_state.next_nonce()
        if nonce_ack != expected_nonce_ack:
            raise ValueError("[device] Nonce mismatch in session_ack.")

        pt_ack = aead_decrypt(session_key, nonce_ack, ct_ack, aad_ack)
        print(f"[device] Session ack decrypted: {pt_ack.decode('utf-8', errors='replace')}")

        # 5) Send one encrypted application message
        msg = "temperature=23.7C; humidity=41%"
        aad = b"app-data|device->server"
        nonce = send_state.next_nonce()
        ct_msg = aead_encrypt(session_key, nonce, msg.encode("utf-8"), aad)

        send_frame(s, {
            "type": "data",
            "nonce_b64": b64e(nonce),
            "aad_b64": b64e(aad),
            "ciphertext_b64": b64e(ct_msg),
        })
        print("[device] Encrypted message sent.")

        # 6) Receive encrypted response
        resp = recv_frame(s)
        if resp.get("type") != "data":
            raise ValueError(f"Unexpected message type: {resp.get('type')}")

        nonce_in = b64d(resp["nonce_b64"])
        aad_in = b64d(resp["aad_b64"])
        ct_in = b64d(resp["ciphertext_b64"])

        expected_nonce_in = recv_state.next_nonce()
        if nonce_in != expected_nonce_in:
            raise ValueError("[device] Nonce mismatch in response (possible replay/out-of-order).")

        pt_in = aead_decrypt(session_key, nonce_in, ct_in, aad_in)
        print(f"[device] Decrypted server response: {pt_in.decode('utf-8', errors='replace')}")
        print("[device] Done.")


if __name__ == "__main__":
    run_device()
