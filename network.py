import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import quantum_filtered_arx as q_arx

# session-based state (In a real app, this would be per-connection)
# For the Gradio UI, we'll keep these global but provide a reset mechanism
chat_history: list[dict] = []
connection: socket.socket | None = None
shared_seed: int = 0xDEADC0DEBEEFCAFE1234567890ABCDEF

telemetry = {
    "last_entropy": 0.0,
    "packets_sent": 0,
    "packets_recv": 0,
    "last_a": 0,
    "last_c": 0,
    "handshake_status": "Idle",
    "is_firing": False,
}


def reset_session():
    global chat_history, telemetry, connection
    chat_history = []
    telemetry = {
        "last_entropy": 0.0,
        "packets_sent": 0,
        "packets_recv": 0,
        "last_a": 0,
        "last_c": 0,
        "handshake_status": "Idle",
        "is_firing": False,
    }
    if connection:
        try:
            connection.close()
        except:
            pass
    connection = None


def set_master_seed(seed_val: int):
    global shared_seed
    shared_seed = seed_val


def perform_ecdh_handshake(sock: socket.socket) -> int:
    """Executes a secure X25519 ECDH handshake and derives a 256-bit seed."""
    # 1. Generate local Keypair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # 2. Key Exchange over socket
    # Send our public key (32 bytes)
    sock.sendall(public_bytes)
    # Receive their public key (32 bytes)
    peer_public_bytes = sock.recv(32)
    if len(peer_public_bytes) < 32:
        raise ConnectionError("Handshake failed: Incomplete public key received.")

    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)

    # 3. Derive Shared Secret
    shared_secret = private_key.exchange(peer_public_key)

    # 4. KDF: Derive the 256-bit MASTER_SEED using HKDF-SHA256
    derived_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"quantum-arx-master-seed-derivation",
    ).derive(shared_secret)

    return int.from_bytes(derived_bytes, "big")


def calculate_entropy(data: bytes) -> float:
    import math
    from collections import Counter

    if not data:
        return 0.0
    count = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in count.values())


def generate_quantum_seed():
    """Generates a fresh 256-bit seed using quantum circuit shots."""
    seed_bits = []
    for _ in range(32):
        seed_bits.extend([0 if b == 1 else 1 for b in q_arx.get_quantum_seed_block()])
    return int("".join(map(str, seed_bits)), 2)


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": [{"type": "text", "text": content}]}


def receive_messages(sock: socket.socket) -> None:
    """Listens for incoming messages with length-prefixed framing."""
    global chat_history, connection
    while True:
        try:
            # 1. Read the 4-byte length prefix
            header = sock.recv(4)
            if not header:
                break
            msg_length = struct.unpack(">I", header)[0]

            # 2. Read the full encrypted payload
            payload = bytearray()
            while len(payload) < msg_length:
                chunk = sock.recv(msg_length - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)

            if len(payload) < msg_length:
                break

            # 3. Decrypt using the shared seed
            decrypted_bytes = q_arx.decrypt(payload, shared_seed)
            message = decrypted_bytes.decode("utf-8")

            # Update telemetry
            telemetry["last_entropy"] = calculate_entropy(payload)
            telemetry["packets_recv"] += 1
            telemetry["is_firing"] = True

            chat_history.append(_msg("assistant", message))

            # Reset firing after a pulse
            threading.Timer(1.0, lambda: telemetry.update({"is_firing": False})).start()
        except Exception as e:
            chat_history.append(_msg("assistant", f"⚠️ [System] Connection lost: {e}"))
            break
    connection = None


def start_host(port: str) -> str:
    """Starts the server and waits for a friend to connect."""
    global connection, chat_history
    if connection:
        return "Already connected!"
    try:
        port = int(port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(1)
        chat_history.append(
            _msg(
                "assistant", f"⚙️ [System] Hosting on port {port}. Waiting for friend..."
            )
        )

        def accept_conn():
            global connection, shared_seed
            conn, addr = server.accept()
            try:
                telemetry["handshake_status"] = "Securing..."
                chat_history.append(
                    _msg("assistant", "🤝 [System] Negotiating Quantum Keys...")
                )

                # Automated Handshake
                new_seed = perform_ecdh_handshake(conn)
                shared_seed = new_seed

                connection = conn
                telemetry["handshake_status"] = "Protected"
                chat_history.append(
                    _msg(
                        "assistant",
                        "✅ [System] Handshake Complete! Master Seed Derived.",
                    )
                )
                receive_messages(conn)
            except Exception as e:
                chat_history.append(
                    _msg("assistant", f"❌ [System] Handshake Failed: {e}")
                )
                conn.close()

        threading.Thread(target=accept_conn, daemon=True).start()
        return "Hosting started..."
    except Exception as e:
        return f"Error: {e}"


def connect_to_host(ip: str, port: str) -> str:
    """Connects to a friend's hosted chat."""
    global connection, chat_history
    if connection:
        return "Already connected!"
    try:
        port = int(port)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))

        telemetry["handshake_status"] = "Securing..."
        chat_history.append(
            _msg("assistant", f"🤝 [System] Negotiating Quantum Keys with {ip}...")
        )

        # Automated Handshake
        new_seed = perform_ecdh_handshake(client)
        shared_seed = new_seed

        connection = client
        telemetry["handshake_status"] = "Protected"
        chat_history.append(_msg("assistant", "✅ [System] Secure Link Ready!"))
        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
        return "Connected and Secured!"
    except Exception as e:
        return f"Error: {e}"


def send_msg(message: str) -> str:
    """Encrypts and sends the message. Returns empty string to clear the input box."""
    global connection, chat_history
    if not message.strip():
        return ""
    if not connection:
        chat_history.append(
            _msg("assistant", "⚠️ [System] You are not connected to anyone!")
        )
        return ""

    chat_history.append(_msg("user", message))
    try:
        # 1. Encrypt using the shared seed
        encrypted_data = q_arx.encrypt(message.encode("utf-8"), shared_seed)

        # Update telemetry
        telemetry["last_entropy"] = calculate_entropy(encrypted_data)
        telemetry["packets_sent"] += 1
        telemetry["is_firing"] = True

        # Reset firing after a pulse
        threading.Timer(1.0, lambda: telemetry.update({"is_firing": False})).start()

        # 2. Prepend 4-byte length header
        header = struct.pack(">I", len(encrypted_data))
        connection.sendall(header + encrypted_data)
    except Exception as e:
        chat_history.append(_msg("assistant", f"⚠️ [System] Failed to send: {e}"))
    return ""


def get_chat_history() -> list[dict]:
    """Returns the current chat history for UI refresh."""
    return chat_history


def get_telemetry() -> dict:
    """Returns current encryption statistics."""
    return telemetry
