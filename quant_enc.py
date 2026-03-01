import argparse
import math
from collections import Counter

import matplotlib.pyplot as plt  # noqa
import pennylane as qml
from faker import Faker
from pennylane import numpy as np  # noqa

# --- DEVICE SETUP ---
# Devices no longer require 'shots' globally (updated for PennyLane best practices)
dev_seed = qml.device("default.qubit", wires=8)
dev_shuffle = qml.device("default.qubit", wires=3)
dev_inject = qml.device("default.qubit", wires=1)


# --- QUANTUM NODES ---
@qml.qnode(dev_seed, shots=1)
def get_quantum_seed_block():
    """Generates 8 bits of entropy via 4 Bell pairs"""
    for i in range(0, 8, 2):
        qml.Hadamard(wires=i)  # Superposition
        qml.CNOT(wires=[i, i + 1])  # Entanglement
    return [qml.sample(qml.PauliZ(i)) for i in range(8)]


@qml.qnode(dev_shuffle, shots=1)
def get_quantum_shuffle_index():
    """Generates a 3-bit quantum index to scramble the LCG output"""
    for i in range(3):
        qml.Hadamard(wires=i)
    return [qml.sample(qml.PauliZ(i)) for i in range(3)]


@qml.qnode(dev_inject, shots=1)
def get_quantum_injection_bit():
    """Generates a single quantum bit for the injection mask."""
    qml.Hadamard(wires=0)
    return qml.sample(qml.PauliZ(0))


# --- HYBRID ALGORITHM ---
def bits_to_int(bits):
    """Converts quantum measurement outcomes to an integer"""
    return int("".join(map(str, [0 if b == 1 else 1 for b in bits])), 2)


def q_ekea_hybrid_cipher(data, master_seed, shuffle_indices):
    """
    Hybrid Cipher integrating LCG with Quantum Shuffling.
    """
    # LCG Constants from Step 5
    a, c, m = 1664525, 1013904223, 2**32
    current_x = master_seed
    output = []

    for i, byte in enumerate(data):
        # 1. Classical Step: Generate LCG byte
        current_x = (a * current_x + c) % m
        lcg_byte = (current_x >> 0) & 0xFF

        # 2. Quantum Step: Use synchronized index to shuffle
        shift = shuffle_indices[i]
        shuffled_byte = ((lcg_byte << shift) | (lcg_byte >> (8 - shift))) & 0xFF

        # 3. Encryption: XOR operation
        output.append(byte ^ shuffled_byte)

    return bytes(output)


def q_ekea_high_entropy_cipher(
    data, master_seed, shuffle_indices, injection_bits, mode="encrypt"
):
    a, c, m = 1664525, 1013904223, 2**32
    current_x = master_seed
    output = []

    prev_ciphertext_byte = 0x00  # Initialization Vector (IV)
    current_byte = 0

    for i, byte in enumerate(data):
        # 1. Autokey LCG: Mutate the LCG state using the previous ciphertext
        # This guarantees that a 1-bit change triggers a massive non-linear avalanche
        current_x = (a * (current_x ^ prev_ciphertext_byte) + c) % m
        lcg_byte = (current_x >> 16) & 0xFF

        # 2. Quantum Shuffle & Injection
        shift = shuffle_indices[i]
        q_inject_bit = 0 if injection_bits[i] == 1 else 1
        injection_mask = 0xFF if q_inject_bit == 1 else 0x00

        shuffled_byte = ((lcg_byte << shift) | (lcg_byte >> (8 - shift))) & 0xFF
        final_key_byte = shuffled_byte ^ injection_mask

        # 3. Encryption / Decryption
        if mode == "encrypt":
            current_byte = byte ^ final_key_byte ^ prev_ciphertext_byte
            prev_ciphertext_byte = current_byte  # Update IV with new ciphertext

        elif mode == "decrypt":
            current_byte = byte ^ final_key_byte ^ prev_ciphertext_byte
            prev_ciphertext_byte = byte  # Update IV with received ciphertext

        output.append(current_byte)

    return bytes(output)


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
    Target: ~50.0%
    """
    if len(cipher1) != len(cipher2):
        raise ValueError("Ciphertexts must be the same length to compare.")

    flipped_bits = 0
    total_bits = len(cipher1) * 8

    for b1, b2 in zip(cipher1, cipher2):
        # XORing the bytes reveals the differences (1s represent flipped bits)
        xor_result = b1 ^ b2
        flipped_bits += bin(xor_result).count("1")

    return (flipped_bits / total_bits) * 100.0


def arg_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("-type", type=str, choices=["text", "para"])
    parser.add_argument("-size", type=int)

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    args = arg_parser()

    # 1. Build 256-bit Seed (32 rounds of 8-bit measurements)
    seed_bits = []
    for _ in range(32):
        seed_bits.extend([0 if b == 1 else 1 for b in get_quantum_seed_block()])
    q_master_seed = int("".join(map(str, seed_bits)), 2)

    # 2. Get input and pre-generate synchronized shuffle indices
    fake = Faker()

    message: str = ""
    if args.type == "text":
        message = fake.text(max_nb_chars=args.size)
    elif args.type == "para":
        message = fake.paragraph(nb_sentences=args.size)

    plaintext = message.encode()

    # We generate the quantum shuffle sequence ONCE for both sides
    q_shuffles = [
        bits_to_int(get_quantum_shuffle_index()) for _ in range(len(plaintext))
    ]
    q_injections = [get_quantum_injection_bit() for _ in range(len(plaintext))]

    assert len(plaintext) == len(q_shuffles), (
        "The length of the `plaintext` and `q_shuffles` are not matching."
    )

    # 3. Run Encryption & Decryption
    ciphertext = q_ekea_high_entropy_cipher(
        plaintext, q_master_seed, q_shuffles, q_injections, mode="encrypt"
    )
    decrypted = q_ekea_high_entropy_cipher(
        ciphertext, q_master_seed, q_shuffles, q_injections, mode="decrypt"
    )

    print(f"\n256-bit Quantum Seed: {hex(q_master_seed)}")
    # print(f"Ciphertext (Hex): {ciphertext.hex()}")
    # print(f"Decrypted Result: {decrypted.decode()}")
    print(f"Shannon Entropy: {calculate_shannon_entropy(ciphertext):.4f}")

    # --- AVALANCHE EFFECT TEST (Using Argparse Inputs) ---
    print("\n--- Running Avalanche Effect Test ---")

    # 1. Use the exact plaintext generated by your argparse inputs
    text1 = plaintext

    # 2. Flip exactly ONE bit in the very first character (LSB of byte 0)
    text2 = bytearray(text1)
    text2[0] = text2[0] ^ 0x01
    text2 = bytes(text2)

    # 3. Encrypt both using the EXACT SAME seed and pre-generated quantum sequences
    cipher1 = q_ekea_high_entropy_cipher(
        text1, q_master_seed, q_shuffles, q_injections, mode="encrypt"
    )
    cipher2 = q_ekea_high_entropy_cipher(
        text2, q_master_seed, q_shuffles, q_injections, mode="encrypt"
    )

    # 4. Calculate the cascade
    ae_score = calculate_avalanche_effect(cipher1, cipher2)

    print(f"Test Configuration: -type {args.type} -size {args.size}")
    print(f"Actual Message Length: {len(text1)} bytes")
    print("Bits Changed in Plaintext: 1 (at position 0)")
    print(f"Avalanche Effect Score: {ae_score:.2f}%")

    # qml.draw_mpl(get_quantum_seed_block)()
    # plt.show()
