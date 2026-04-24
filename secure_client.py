import socket
import struct
import quantum_filtered_arx as q_arx
import sys

# Pre-shared Master Seed (Must be identical on both client and server)
MASTER_SEED = 0xDEADC0DEBEEFCAFE1234567890ABCDEF

def send_msg(sock, msg_bytes):
    # Prefix each message with a 4-byte length (network byte order)
    msg_bytes = struct.pack('>I', len(msg_bytes)) + msg_bytes
    sock.sendall(msg_bytes)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the actual message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

import argparse

def main():
    parser = argparse.ArgumentParser(description="Secure Quantum-ARX Client")
    parser.add_argument("--host", default='127.0.0.1', help="Server IP to connect to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Server port (default: 9999)")
    args = parser.parse_args()

    host = args.host
    port = args.port

    print(f"[*] Connecting to {host}:{port}")
    print("[*] Type your message or 'exit' to quit.")

    try:
        while True:
            message_text = input("\n[>] Message: ")
            if message_text.lower() in ['exit', 'quit']:
                break

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((host, port))

                # 1. Encrypt message
                encrypted_data = q_arx.encrypt(message_text.encode('utf-8'), MASTER_SEED)
                
                # 2. Send encrypted message
                send_msg(client_socket, encrypted_data)

                # 3. Receive encrypted response
                encrypted_response = recv_msg(client_socket)
                if encrypted_response:
                    # 4. Decrypt response
                    decrypted_response = q_arx.decrypt(encrypted_response, MASTER_SEED)
                    print(f"[!] Server Response: {decrypted_response.decode('utf-8')}")

            except ConnectionRefusedError:
                print("[!] Error: Could not connect to the server.")
                break
            finally:
                client_socket.close()

    except KeyboardInterrupt:
        print("\n[*] Client exiting.")

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
