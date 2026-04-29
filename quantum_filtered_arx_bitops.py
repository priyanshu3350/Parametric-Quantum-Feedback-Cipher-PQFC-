"""
Quantum-Filtered ARX Stream Cipher — Bitwise-Optimised Edition
===============================================================
Functionally identical to quantum_filtered_arx.py, but rewritten
to use bitwise operators in place of arithmetic wherever possible.

Key changes from the original:
  1.  % 256      →  & 0xFF           (byte reduction)
  2.  % 2**32    →  & 0xFFFFFFFF     (32-bit state masking)
  3.  % 8        →  & 0x7            (rotation shift masking)
  4.  * 8        →  << 3             (byte-offset multiplication)
  5.  * 32       →  << 5             (subkey-offset multiplication)
  6.  len * 8    →  len << 3         (total-bits calculation)
  7.  2**32 - 1  →  0xFFFFFFFF       (constant folding)
  8.  bin(x).count('1') → inline bit-parallel Hamming weight
  9.  Pre-allocated output bytearrays (no per-byte .append())
"""

import argparse
import math
import time
from collections import Counter

import numpy as np
import pennylane as qml
from faker import Faker

# ==========================================
# Constants
# ==========================================
_MASK8 = 0xFF
_MASK32 = 0xFFFFFFFF

# ==========================================
# Quantum Layer (PennyLane Implementation)
# ==========================================

dev_seed = qml.device("lightning.qubit", wires=8)
# Initialize a 4-qubit quantum simulator device
dev_dynamic = qml.device("lightning.qubit", wires=4)


@qml.qnode(dev_seed, shots=1)
def get_quantum_seed_block():
    for i in range(8):
        qml.Hadamard(wires=i)
    return [qml.sample(qml.PauliZ(i)) for i in range(8)]


@qml.qnode(dev_dynamic)
def pqc_circuit(angles):
    """
    A 4-qubit Parameterized Quantum Circuit (PQC).
    """
    # 1. Feature Encoding: Apply parameterized Ry rotations
    for i in range(4):
        qml.RY(angles[i], wires=i)

    # 2. Entanglement Layer: Create dependencies between qubits
    qml.CNOT(wires=[0, 1])
    qml.CNOT(wires=[1, 2])
    qml.CNOT(wires=[2, 3])
    qml.CNOT(wires=[3, 0])

    # 3. Measurement: Return continuous Pauli-Z expectation values
    return [qml.expval(qml.PauliZ(i)) for i in range(4)]


def simulate_pqc(state_32bit):
    """
    Maps the classical 32-bit state to rotation angles and executes the quantum circuit.
    Uses << 3 instead of * 8 for byte-offset computation.
    """
    angles = [
        ((state_32bit >> (i << 3)) & _MASK8) / 255.0 * np.pi
        for i in range(4)
    ]
    return np.array(pqc_circuit(angles))


# ==========================================
# Classical Cryptographic Layer
# ==========================================


def update_lcg_params(z_expects):
    """
    Generates new LCG parameters using sanitized quantum expectation values.
    """
    c_raw = int(float(abs(z_expects[0])) * _MASK32)
    c_new = c_raw | 1  # Force odd → set bit 0

    a_raw = int(float(abs(z_expects[1])) * _MASK32)
    a_new = (a_raw & ~3) | 1  # Force a ≡ 1 (mod 4)

    return a_new, c_new


def generate_qpp_sbox(z_expects):
    """
    Generates a dynamic Quantum Permutation Pad (QPP) / S-Box.
    Seed bounded to 32 bits with bitmask instead of modulo.
    """
    seed = int(float(abs(z_expects[2])) * _MASK32) & _MASK32
    rng = np.random.RandomState(seed)

    sbox = np.arange(256, dtype=np.uint8)
    rng.shuffle(sbox)
    return sbox


def rotl8(x, shift):
    """8-bit left circular shift (& 0x7 replaces % 8, & 0xFF replaces % 256)."""
    shift &= 0x7
    return ((x << shift) | (x >> (8 - shift))) & _MASK8


def rotr8(x, shift):
    """8-bit right circular shift (& 0x7 replaces % 8, & 0xFF replaces % 256)."""
    shift &= 0x7
    return ((x >> shift) | (x << (8 - shift))) & _MASK8


def _popcount8(x):
    """Inline bit-parallel Hamming weight for an 8-bit value."""
    x = x - ((x >> 1) & 0x55)
    x = (x & 0x33) + ((x >> 2) & 0x33)
    return (x + (x >> 4)) & 0x0F


def encrypt(plaintext, master_seed):
    n = len(plaintext)
    ciphertext = bytearray(n)  # pre-allocate instead of append

    # Split the 256-bit master seed into eight 32-bit subkeys
    # << 5 replaces * 32
    subkeys = [(master_seed >> (i << 5)) & _MASK32 for i in range(8)]

    # Initialize the state using the first 32-bit subkey
    x_n = subkeys[0]
    prev_c = 0x00

    for idx in range(n):
        p = plaintext[idx]

        z_expects = simulate_pqc(x_n)
        a_i, c_i = update_lcg_params(z_expects)
        sbox = generate_qpp_sbox(z_expects)

        raw_lcg_byte = (x_n >> 24) & _MASK8

        # Cast the S-Box output to a standard Python int
        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        # & 0xFF replaces % 256
        modular_addition = (p + k_i) & _MASK8
        rotated = rotl8(modular_addition, r_i)
        c_i_byte = rotated ^ prev_c

        ciphertext[idx] = c_i_byte

        prev_c = c_i_byte

        # KEY CYCLING: & 0x7 replaces % 8
        current_subkey = subkeys[idx & 0x7]

        # Inject the subkey into the state using XOR
        # & 0xFFFFFFFF replaces % (2**32)
        x_n = (a_i * (x_n ^ prev_c ^ current_subkey) + c_i) & _MASK32

    return ciphertext


def decrypt(ciphertext, master_seed):
    n = len(ciphertext)
    plaintext = bytearray(n)  # pre-allocate instead of append

    # Split the 256-bit master seed into eight 32-bit subkeys
    subkeys = [(master_seed >> (i << 5)) & _MASK32 for i in range(8)]

    # Initialize the state using the first 32-bit subkey
    x_n = subkeys[0]
    prev_c = 0x00

    for idx in range(n):
        c = ciphertext[idx]

        z_expects = simulate_pqc(x_n)

        a_i, c_i = update_lcg_params(z_expects)
        sbox = generate_qpp_sbox(z_expects)

        raw_lcg_byte = (x_n >> 24) & _MASK8

        # Cast the S-Box output to a standard Python int
        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        un_xor = c ^ prev_c
        un_rot = rotr8(un_xor, r_i)
        # & 0xFF replaces % 256
        p = (un_rot - k_i) & _MASK8

        plaintext[idx] = p

        prev_c = c

        # KEY CYCLING: & 0x7 replaces % 8
        current_subkey = subkeys[idx & 0x7]

        # Inject the subkey into the state using XOR
        x_n = (a_i * (x_n ^ prev_c ^ current_subkey) + c_i) & _MASK32

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
    """
    Calculates the percentage of flipped bits between two ciphertexts.
    Uses inline bit-parallel popcount instead of bin(x).count('1').
    """
    if len(cipher1) != len(cipher2):
        raise ValueError("Ciphertexts must be the same length to compare.")

    flipped_bits = 0
    total_bits = len(cipher1) << 3  # << 3 replaces * 8

    for b1, b2 in zip(cipher1, cipher2):
        flipped_bits += _popcount8(b1 ^ b2)

    return (flipped_bits / total_bits) * 100.0


# ==========================================
# Execution and Verification
# ==========================================
if __name__ == "__main__":
    args = arg_parser()

    # 1. Build 256-bit Seed (32 rounds of 8-bit measurements)
    seed_bits = []
    for _ in range(32):
        seed_bits.extend([0 if b == 1 else 1 for b in get_quantum_seed_block()])
    q_master_seed = int("".join(map(str, seed_bits)), 2)

    # 2. Get input
    fake = Faker()
    message = ""
    if args.type == "text":
        message = fake.text(max_nb_chars=args.size)
    elif args.type == "para":
        message = fake.paragraph(nb_sentences=args.size)

    message = message.encode()

    shared_master_seed = q_master_seed

    print("\n--- Benchmarking (Bitwise-Optimised) ---")
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
    print(
        f"Total Overhead (including verification): {total_end - total_start:.4f} seconds"
    )

    # Change in Message Length
    len_plain = len(message)
    len_cipher = len(encrypted_data)
    print(
        f"Length Change: {len_cipher - len_plain} bytes (Plaintext: {len_plain} -> Ciphertext: {len_cipher})"
    )

    assert message == decrypted_data, "Decryption failed!"
    print("\nDecryption verified OK.")

    print(f"\n256-bit Quantum Seed: {hex(q_master_seed)}")
    print(f"Message Length: {len(message) / 1024:.2f} KB")
    print(f"Shannon Entropy: {calculate_shannon_entropy(encrypted_data):.4f}")

    # 4. Avalanche Effect Test
    print("\nRunning Avalanche Effect Test...")

    text1 = message
    text2 = bytearray(text1)
    text2[0] = text2[0] ^ 0x01
    text2 = bytes(text2)

    cipher1 = encrypt(text1, shared_master_seed)
    cipher2 = encrypt(text2, shared_master_seed)

    ae_score = calculate_avalanche_effect(cipher1, cipher2)

    print(f"Actual Message Length: {len(text1) / 1024:.2f} KB")
    print("Bits Changed in Plaintext: 1 (at position 0)")
    print(f"Avalanche Effect Score: {ae_score:.2f}%\n")
