import argparse
import math
import os
import time
from collections import Counter

import numpy as np
from faker import Faker

# ==========================================
# Quantum Layer (Numpy Fast Implementation)
# ==========================================


def simulate_pqc(state_32bit):
    """
    Pure NumPy mathematical equivalent of the original 4-qubit
    Parameterized Quantum Circuit (PQC).
    Executes massively faster than PennyLane by bypassing graph compilation.
    """
    angles = [((state_32bit >> (8 * i)) & 0xFF) / 255.0 * np.pi for i in range(4)]

    # 4 qubits -> 16 states (|0000> to |1111>)
    state = np.zeros(16, dtype=np.float64)

    # 1. Feature Encoding: Apply parameterized Ry rotations
    # Since we start at |0000>, applying Ry to |0> gives [cos, sin].
    # Amplitudes for basis state |b0 b1 b2 b3> is the product of corresponding amps
    c = [math.cos(a / 2) for a in angles]
    s = [math.sin(a / 2) for a in angles]

    for i in range(16):
        amp = 1.0
        amp *= s[0] if (i & 8) else c[0]
        amp *= s[1] if (i & 4) else c[1]
        amp *= s[2] if (i & 2) else c[2]
        amp *= s[3] if (i & 1) else c[3]
        state[i] = amp

    # 2. Entanglement Layer: CNOT ring
    # CNOT(0,1), CNOT(1,2), CNOT(2,3), CNOT(3,0)

    # CNOT(0,1): wire 0 (bit 8) -> target wire 1 (bit 4)
    st_01 = np.copy(state)
    for i in [8, 9, 10, 11, 12, 13, 14, 15]:
        st_01[i] = state[i ^ 4]

    # CNOT(1,2): wire 1 (bit 4) -> target wire 2 (bit 2)
    st_12 = np.copy(st_01)
    for i in [4, 5, 6, 7, 12, 13, 14, 15]:
        st_12[i] = st_01[i ^ 2]

    # CNOT(2,3): wire 2 (bit 2) -> target wire 3 (bit 1)
    st_23 = np.copy(st_12)
    for i in [2, 3, 6, 7, 10, 11, 14, 15]:
        st_23[i] = st_12[i ^ 1]

    # CNOT(3,0): wire 3 (bit 1) -> target wire 0 (bit 8)
    st_final = np.copy(st_23)
    for i in [1, 3, 5, 7, 9, 11, 13, 15]:
        st_final[i] = st_23[i ^ 8]

    probs = st_final**2

    # 3. Measurement: Pauli-Z expectation values
    expects = []
    expects.append(np.sum(probs[0:8]) - np.sum(probs[8:16]))
    expects.append(
        np.sum(probs[[0, 1, 2, 3, 8, 9, 10, 11]])
        - np.sum(probs[[4, 5, 6, 7, 12, 13, 14, 15]])
    )
    expects.append(
        np.sum(probs[[0, 1, 4, 5, 8, 9, 12, 13]])
        - np.sum(probs[[2, 3, 6, 7, 10, 11, 14, 15]])
    )
    expects.append(
        np.sum(probs[[0, 2, 4, 6, 8, 10, 12, 14]])
        - np.sum(probs[[1, 3, 5, 7, 9, 11, 13, 15]])
    )

    return np.array(expects, dtype=np.float64)


# ==========================================
# Classical Cryptographic Layer
# ==========================================


def update_lcg_params(z_expects):
    """
    Generates new LCG parameters using sanitized quantum expectation values.
    """
    c_raw = int(float(abs(z_expects[0])) * (2**32 - 1))
    c_new = c_raw | 1  # Force odd

    a_raw = int(float(abs(z_expects[1])) * (2**32 - 1))
    a_new = (a_raw & ~3) | 1  # Force a_new = 1 mod 4

    return a_new, c_new


def generate_qpp_sbox(z_expects):
    """
    Generates a dynamic Quantum Permutation Pad (QPP) / S-Box.
    """
    seed = int(float(abs(z_expects[2])) * (2**32 - 1)) % (2**32)
    rng = np.random.RandomState(seed)

    sbox = np.arange(256, dtype=np.uint8)
    rng.shuffle(sbox)
    return sbox


def rotl8(x, shift):
    """8-bit left circular shift"""
    shift %= 8
    return ((x << shift) | (x >> (8 - shift))) & 0xFF


def rotr8(x, shift):
    """8-bit right circular shift"""
    shift %= 8
    return ((x >> shift) | (x << (8 - shift))) & 0xFF


def encrypt(plaintext, master_seed):
    ciphertext = bytearray()

    x_n = master_seed & 0xFFFFFFFF
    prev_c = 0x00

    for p in plaintext:
        z_expects = simulate_pqc(x_n)
        a_i, c_i = update_lcg_params(z_expects)
        sbox = generate_qpp_sbox(z_expects)

        raw_lcg_byte = (x_n >> 24) & 0xFF

        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        modular_addition = (p + k_i) % 256
        rotated = rotl8(modular_addition, r_i)
        c_i_byte = rotated ^ prev_c

        ciphertext.append(c_i_byte)

        prev_c = c_i_byte
        x_n = (a_i * (x_n ^ prev_c) + c_i) % (2**32)

    return ciphertext


def decrypt(ciphertext, master_seed):
    plaintext = bytearray()

    x_n = master_seed & 0xFFFFFFFF
    prev_c = 0x00

    for c in ciphertext:
        z_expects = simulate_pqc(x_n)

        a_i, c_i = update_lcg_params(z_expects)
        sbox = generate_qpp_sbox(z_expects)

        raw_lcg_byte = (x_n >> 24) & 0xFF

        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        un_xor = c ^ prev_c
        un_rot = rotr8(un_xor, r_i)
        p = (un_rot - k_i) % 256

        plaintext.append(p)

        prev_c = c
        x_n = (a_i * (x_n ^ prev_c) + c_i) % (2**32)

    return plaintext


def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-type", type=str, choices=["text", "para"], required=True)
    parser.add_argument("-size", type=int, required=True)
    parser.add_argument("--plot", required=False, action="store_true")
    return parser.parse_args()


def calculate_shannon_entropy(data):
    """Measures randomness and diffusion in the ciphertext."""
    if not data:
        return 0
    count = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in count.values())


def calculate_avalanche_effect(cipher1, cipher2):
    """Calculates the percentage of flipped bits between two ciphertexts."""
    if len(cipher1) != len(cipher2):
        raise ValueError("Ciphertexts must be the same length to compare.")

    flipped_bits = 0
    total_bits = len(cipher1) * 8

    for b1, b2 in zip(cipher1, cipher2):
        xor_result = b1 ^ b2
        flipped_bits += bin(xor_result).count("1")

    return (flipped_bits / total_bits) * 100.0


# ==========================================
# Execution and Verification
# ==========================================
if __name__ == "__main__":
    args = arg_parser()

    # Get input
    fake = Faker()
    message = ""
    if args.type == "text":
        message = fake.text(max_nb_chars=args.size)
    elif args.type == "para":
        message = fake.paragraph(nb_sentences=args.size)

    message = message.encode()

    shared_master_seed = int.from_bytes(os.urandom(32), byteorder="big")

    print("\n--- FAST NUMPY Benchmarking ---")
    total_start = time.time()

    enc_start = time.time()
    encrypted_data = encrypt(message, shared_master_seed)
    enc_end = time.time()
    print(f"Encryption Time: {enc_end - enc_start:.4f} seconds")

    dec_start = time.time()
    decrypted_data = decrypt(encrypted_data, shared_master_seed)
    dec_end = time.time()
    print(f"Decryption Time: {dec_end - dec_start:.4f} seconds")

    total_end = time.time()
    print(f"Total Time: {total_end - total_start:.4f} seconds")

    assert message == decrypted_data, "Decryption failed!"
    print("\nDecryption verified OK.")
