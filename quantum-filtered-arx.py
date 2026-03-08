import argparse
import math
from collections import Counter

import numpy as np
import pennylane as qml
from faker import Faker

# ==========================================
# Quantum Layer (PennyLane Implementation)
# ==========================================

dev_seed = qml.device("default.qubit", wires=8)
# Initialize a 4-qubit quantum simulator device
dev_dynamic = qml.device("default.qubit", wires=4)


@qml.qnode(dev_seed, shots=1)
def get_quantum_seed_block():
    """Generates 8 bits of entropy via 4 Bell pairs."""
    for i in range(0, 8, 2):
        qml.Hadamard(wires=i)
        # qml.CNOT(wires=[i, i + 1])
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
    """
    angles = [((state_32bit >> (8 * i)) & 0xFF) / 255.0 * np.pi for i in range(4)]
    return np.array(pqc_circuit(angles))


# ==========================================
# Classical Cryptographic Layer
# ==========================================


def update_lcg_params(z_expects):
    """
    Generates new LCG parameters using sanitized quantum expectation values.
    """
    # Explicitly cast through float to int to strip tensor/numpy types
    c_raw = int(float(abs(z_expects[0])) * (2**32 - 1))
    c_new = c_raw | 1  # Force odd

    a_raw = int(float(abs(z_expects[1])) * (2**32 - 1))
    a_new = (a_raw & ~3) | 1  # Force a_new = 1 mod 4

    return a_new, c_new


# def generate_qpp_sbox(z_expects):
#     """
#     Generates a dynamic Quantum Permutation Pad (QPP) / S-Box.
#     """
#     # Extract seed, strip types, and strictly bound it to 32-bit max for RandomState
#     seed = int(float(abs(z_expects[2])) * (2**32 - 1)) % (2**32)
#     rng = np.random.RandomState(seed)

#     sbox = np.arange(256, dtype=np.uint8)
#     rng.shuffle(sbox)
#     return sbox


def generate_qpp_sbox(z_expects, state_32bit):
    """
    Generates a dynamic S-Box using a Parameter-Free Quantum-Coupled Map.
    Eliminates all arbitrary constants by tightly coupling the continuous
    quantum expectation values with the discrete 32-bit classical state.
    """
    chaotic_sequence = np.zeros(256, dtype=np.float64)

    # Base continuous variables derived strictly from quantum measurements
    q_val = float(z_expects[1])
    q_step = float(z_expects[2])

    for i in range(256):
        # Extract a state byte (0-255) cyclically to act as a classical dynamic perturbator
        state_byte = (state_32bit >> ((i % 4) * 8)) & 0xFF

        # Non-linear coupling of quantum continuous space and classical discrete space.
        # The division by 255.0 naturally scales the byte to  based on its 8-bit size.
        q_val = np.sin(q_val + q_step + (state_byte / 255.0) * np.pi)

        chaotic_sequence[i] = q_val

        # Mutate the step using another qubit's expectation to guarantee chaotic divergence
        q_step = np.cos(q_step + float(z_expects[i % 4]))

    # Bridge the continuous domain to discrete cryptography via argsort.
    # argsort mathematically guarantees a perfect bijection (0 to 255) with no missing bytes.
    sbox = np.argsort(chaotic_sequence).astype(np.uint8)

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
        sbox = generate_qpp_sbox(z_expects, x_n)

        raw_lcg_byte = (x_n >> 24) & 0xFF

        # Cast the S-Box output to a standard Python int to prevent NumPy 2.0 OverflowErrors
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
        sbox = generate_qpp_sbox(z_expects, x_n)

        raw_lcg_byte = (x_n >> 24) & 0xFF

        # Cast the S-Box output to a standard Python int
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

    # print(f"Original Plaintext: {message}")

    encrypted_data = encrypt(message, shared_master_seed)
    # print(f"Ciphertext (Hex):   {encrypted_data.hex()}")

    decrypted_data = decrypt(encrypted_data, shared_master_seed)
    # print(f"Decrypted Data:     {decrypted_data.decode('utf-8', errors='ignore')}")

    assert message == decrypted_data, "Decryption failed!"

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
