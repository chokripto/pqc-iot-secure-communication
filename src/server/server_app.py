import os
import socket
from typing import Dict, Any

import oqs

from src.common.crypto_utils import (
    b64e, b64d, NonceState,
    aead_encrypt, aead_decrypt,
    short_fingerprint
)
from src.common.hkdf import derive_session_key
from src.common.message import send_frame, recv_frame

HOST = "0.0.0.0"
PORT = 9000
KEM_ALG = "Kyber512"


def build_info(session_id: bytes) -> bytes:
    return b"pqc-iot-demo|" + session_id


def run_server() -> None:
    # Ensure Kyber is enabled in this OQS build
    assert oqs.is_kem_enabled(KEM_ALG), f"{KEM_ALG} is not enabled in this OQS build"

    # Create KEM instance and generate keypair
    kem = oqs.KeyEncapsulation(KEM_ALG)
    pk = kem.generate_keypair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[server] Listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"[server] Connection from {addr}")

            session_id = os.urandom(16)
            salt = os.urandom(16)
            server_nonce_prefix = os.urandom(4)

            # 1) Send server_hello
            send_frame(conn, {
                "type": "server_hello",
                "kem_alg": KEM_ALG,
                "pk_b64": b64e(pk),
                "session_id_b64": b64e(session_id),
                "salt_b64": b64e(salt),
                "server_nonce_prefix_b64": b64e(server_nonce_prefix),
            })

            # 2) Receive client_kem
            msg = recv_frame(conn)
            if msg.get("type") != "client_kem":
                raise ValueError(f"Unexpected message type: {msg.get('type')}")
            if msg.get("kem_alg") != KEM_ALG:
                raise ValueError("KEM algorithm mismatch.")

            ct = b64d(msg["ct_b64"])
            client_nonce_prefix = b64d(msg["client_nonce_prefix_b64"])

            # 3) Decapsulate shared secret
            shared_secret = kem.decap_secret(ct)

            info = build_info(session_id)
            session_key = derive_session_key(shared_secret, salt=salt, info=info, length=32)

            print("[server] Session established.")
            print(f"[server] session_id(fp)={short_fingerprint(session_id)} salt(fp)={short_fingerprint(salt)}")
            print(f"[server] ss(fp)={short_fingerprint(shared_secret)} key(fp)={short_fingerprint(session_key)}")

            # Nonces: server->device uses server prefix; device->server uses client prefix
            send_state = NonceState(prefix4=server_nonce_prefix, counter=0)
            recv_state = NonceState(prefix4=client_nonce_prefix, counter=0)

            # 4) Encrypted session ack
            aad = b"session-ack|server"
            nonce = send_state.next_nonce()
            ct_ack = aead_encrypt(session_key, nonce, b"OK", aad)

            send_frame(conn, {
                "type": "session_ack",
                "nonce_b64": b64e(nonce),
                "aad_b64": b64e(aad),
                "ciphertext_b64": b64e(ct_ack),
            })

            # 5) Receive one encrypted application message
            data_msg: Dict[str, Any] = recv_frame(conn)
            if data_msg.get("type") != "data":
                raise ValueError(f"Unexpected message type: {data_msg.get('type')}")

            nonce_in = b64d(data_msg["nonce_b64"])
            aad_in = b64d(data_msg["aad_b64"])
            ciphertext_in = b64d(data_msg["ciphertext_b64"])

            expected_nonce = recv_state.next_nonce()
            if nonce_in != expected_nonce:
                raise ValueError("[server] Nonce mismatch (possible replay/out-of-order).")

            plaintext = aead_decrypt(session_key, nonce_in, ciphertext_in, aad_in)
            print(f"[server] Decrypted message from device: {plaintext.decode('utf-8', errors='replace')}")

            # 6) Send encrypted response
            response = b"ACK: message received securely"
            aad_out = b"app-data|server->device"
            nonce_out = send_state.next_nonce()
            ct_out = aead_encrypt(session_key, nonce_out, response, aad_out)

            send_frame(conn, {
                "type": "data",
                "nonce_b64": b64e(nonce_out),
                "aad_b64": b64e(aad_out),
                "ciphertext_b64": b64e(ct_out),
            })

            print("[server] Response sent. Closing connection.")


if __name__ == "__main__":
    run_server()
