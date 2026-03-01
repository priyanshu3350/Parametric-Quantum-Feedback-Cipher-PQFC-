import json
import socket
import threading


# --- Logic from python_code/enc_dec.py ---
def encryption(text, key=85):
    ascii_text = [ord(char) for char in text]
    a = 1664525
    c = 1013904223
    m = 256
    shared_key = []
    for _ in range(len(text)):
        key = (key * a + c) % m
        shared_key.append(key)
    encrypted_text = [
        char_val ^ key_val for char_val, key_val in zip(ascii_text, shared_key)
    ]
    return encrypted_text, shared_key


def decryption(encrypted_text, shared_key):
    decrypted_ascii = [
        enc_val ^ key_val for enc_val, key_val in zip(encrypted_text, shared_key)
    ]
    return "".join(chr(val) for val in decrypted_ascii)


# -------------------------------------------------------------


def receive_messages(conn):
    """
    Listens for incoming messages, decrypts them, and prints them.
    """
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break

            # 1. Deserialize JSON
            packet = json.loads(data.decode("utf-8"))
            encrypted_text = packet["encrypted_text"]
            shared_key = packet["shared_key"]

            # 2. Decrypt
            decrypted_msg = decryption(encrypted_text, shared_key)

            # 3. Print (Use \r to clear the current input line visual glitch)
            print(f"\n\r[Client]: {decrypted_msg}")
            print("You: ", end="", flush=True)

        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Error receiving: {e}")
            break


def start_server():
    host = "0.0.0.0"  # Listen on all interfaces
    port = 65432

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()

    print(f"Server listening on port {port}...")
    conn, addr = server.accept()
    print(f"Connected to {addr}")

    # Start a separate thread to handle incoming messages
    thread = threading.Thread(target=receive_messages, args=(conn,))
    thread.daemon = True
    thread.start()

    # Main loop for sending messages
    while True:
        msg = input("You: ")
        if msg.lower() == "exit":
            break

        # 1. Encrypt
        encrypted_text, shared_key = encryption(msg)

        # 2. Package (Send both text and key so receiver can decrypt)
        packet = {"encrypted_text": encrypted_text, "shared_key": shared_key}

        # 3. Send
        conn.sendall(json.dumps(packet).encode("utf-8"))

    conn.close()


if __name__ == "__main__":
    start_server()
