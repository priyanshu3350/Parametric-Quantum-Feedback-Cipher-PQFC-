import json
import socket
import threading

from crypto import decryption, encryption

# Shared state — messages format: {"role": "user"|"assistant", "content": "..."}
chat_history: list[dict] = []
connection: socket.socket | None = None


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def receive_messages(sock: socket.socket) -> None:
    """Listens for incoming messages in a background thread."""
    global chat_history, connection
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            packet = json.loads(data.decode("utf-8"))
            decrypted_msg = decryption(packet["encrypted_text"], packet["shared_key"])
            chat_history.append(_msg("assistant", f"🟢 Friend: {decrypted_msg}"))
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
            global connection
            conn, addr = server.accept()
            connection = conn
            chat_history.append(
                _msg("assistant", f"✅ [System] Friend connected from {addr[0]}!")
            )
            receive_messages(conn)

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
        connection = client
        chat_history.append(_msg("assistant", f"✅ [System] Connected to {ip}:{port}!"))
        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
        return "Connected!"
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
        encrypted_text, shared_key = encryption(message)
        packet = {"encrypted_text": encrypted_text, "shared_key": shared_key}
        connection.sendall(json.dumps(packet).encode("utf-8"))
    except Exception as e:
        chat_history.append(_msg("assistant", f"⚠️ [System] Failed to send: {e}"))
    return ""


def get_chat_history() -> list[dict]:
    """Returns the current chat history for UI refresh."""
    return chat_history
