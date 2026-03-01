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


def receive_messages(sock):
    """
    Listens for incoming messages, decrypts them, and prints them.
    """
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            packet = json.loads(data.decode("utf-8"))
            encrypted_text = packet["encrypted_text"]
            shared_key = packet["shared_key"]

            decrypted_msg = decryption(encrypted_text, shared_key)

            print(f"\n\r[Server]: {decrypted_msg}")
            print("You: ", end="", flush=True)

        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Error receiving: {e}")
            break


def start_client():
    host = input("Enter Server IP (or 'localhost'): ")
    port = 65432

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((host, port))
        print("Connected to Server! Type messages below.")

        # Start a separate thread to receive messages
        thread = threading.Thread(target=receive_messages, args=(client,))
        thread.daemon = True
        thread.start()

        # Main loop for sending messages
        while True:
            msg = input("You: ")
            if msg.lower() == "exit":
                break

            # 1. Encrypt
            encrypted_text, shared_key = encryption(msg)

            # 2. Package
            packet = {"encrypted_text": encrypted_text, "shared_key": shared_key}

            # 3. Send
            client.sendall(json.dumps(packet).encode("utf-8"))

    except Exception as e:
        print(f"Could not connect: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    start_client()
