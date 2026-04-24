import socket
import struct
import quantum_filtered_arx as q_arx

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
    parser = argparse.ArgumentParser(description="Secure Quantum-ARX Server")
    parser.add_argument("--host", default='0.0.0.0', help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9999, help="Port to listen on (default: 9999)")
    args = parser.parse_args()

    host = args.host
    port = args.port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"[*] Secure Server listening on {host}:{port}")
    print("[*] Using Quantum-Filtered ARX Encryption")

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"[*] Accepted connection from {addr}")

            # 1. Receive encrypted message
            encrypted_data = recv_msg(conn)
            if encrypted_data:
                print(f"[<] Received {len(encrypted_data)} bytes of encrypted data")

                # 2. Decrypt message
                decrypted_bytes = q_arx.decrypt(encrypted_data, MASTER_SEED)
                message = decrypted_bytes.decode('utf-8')
                print(f"[!] Decrypted Message: {message}")

                # 3. Send encrypted response
                response = f"ACK: Received your message '{message[:10]}...'"
                print(f"[>] Sending encrypted response: {response}")
                encrypted_response = q_arx.encrypt(response.encode('utf-8'), MASTER_SEED)
                send_msg(conn, encrypted_response)

            conn.close()
            print(f"[*] Connection closed with {addr}")

    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
