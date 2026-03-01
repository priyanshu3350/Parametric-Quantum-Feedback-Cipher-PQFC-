import argparse
import math
from collections import Counter

import matplotlib.pyplot as plt  # noqa
import pennylane as qml
from faker import Faker

# DEVICE SETUP
dev_seed = qml.device("default.qubit", wires=8)
dev_dynamic = qml.device("default.qubit", wires=4)


# QUANTUM NODES
@qml.qnode(dev_seed, shots=1)
def get_quantum_seed_block():
    """Generates 8 bits of entropy via 4 Bell pairs."""
    for i in range(0, 8, 2):
        qml.Hadamard(wires=i)
        qml.CNOT(wires=[i, i + 1])
    return [qml.sample(qml.PauliZ(i)) for i in range(8)]


@qml.qnode(dev_dynamic)
def get_quantum_feedback_params(prev_cipher_byte):
    """Encodes the previous ciphertext as an angle to mutate the quantum state."""
    theta = (prev_cipher_byte / (2**32 - 1)) * math.pi

    for i in range(4):
        qml.RY(theta, wires=i)

    qml.CNOT(wires=[0, 1])
    qml.CNOT(wires=[1, 2])
    qml.CNOT(wires=[2, 3])

    return [qml.expval(qml.PauliZ(i)) for i in range(4)]


# HYBRID ALGORITHM
def q_ekea_high_entropy_cipher(data, master_seed, mode="encrypt"):
    a, c, m = 1664525, 1013904223, 2**32
    current_x = master_seed
    output = []

    prev_ciphertext_byte = 0x00
    current_byte = 0

    for byte in data:
        # 1. Autokey Feedback: Scramble the 32-bit state
        current_x = (a * (current_x ^ prev_ciphertext_byte) + c) % m
        lcg_byte = (current_x >> 8) & 0xFF

        # 2. Live Quantum Feedback Circuit
        exp_values = get_quantum_feedback_params(prev_ciphertext_byte)

        # Convert continuous expectation values (-1.0 to 1.0) into discrete binary bits
        q_bits = [1 if val > 0 else 0 for val in exp_values]

        shift = int("".join(map(str, q_bits[:3])), 2)
        q_inject_bit = q_bits[3]

        injection_mask = 0xFF if q_inject_bit == 1 else 0x00

        # 3. Shuffle and Inject
        shuffled_byte = ((lcg_byte << shift) | (lcg_byte >> (8 - shift))) & 0xFF
        final_key_byte = shuffled_byte ^ injection_mask

        # 4. Encryption / Decryption
        if mode == "encrypt":
            current_byte = byte ^ final_key_byte ^ prev_ciphertext_byte
            prev_ciphertext_byte = current_byte
        elif mode == "decrypt":
            current_byte = byte ^ final_key_byte ^ prev_ciphertext_byte
            prev_ciphertext_byte = byte

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
    """Calculates the percentage of flipped bits between two ciphertexts."""
    if len(cipher1) != len(cipher2):
        raise ValueError("Ciphertexts must be the same length to compare.")

    flipped_bits = 0
    total_bits = len(cipher1) * 8

    for b1, b2 in zip(cipher1, cipher2):
        xor_result = b1 ^ b2
        flipped_bits += bin(xor_result).count("1")

    return (flipped_bits / total_bits) * 100.0


def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-type", type=str, choices=["text", "para"], required=True)
    parser.add_argument("-size", type=int, required=True)
    parser.add_argument("--plot", required=False, action="store_true")
    return parser.parse_args()


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

    plaintext = message.encode()

    # 3. Run Encryption and Decryption
    ciphertext = q_ekea_high_entropy_cipher(plaintext, q_master_seed, mode="encrypt")
    decrypted = q_ekea_high_entropy_cipher(ciphertext, q_master_seed, mode="decrypt")

    assert plaintext == decrypted, "Decryption failed! Output does not match input."

    print(f"\n256-bit Quantum Seed: {hex(q_master_seed)}")
    print(f"Message Length: {len(plaintext)} bytes")
    print(f"Shannon Entropy: {calculate_shannon_entropy(ciphertext):.4f}")

    # 4. Avalanche Effect Test
    print("\nRunning Avalanche Effect Test...")

    text1 = plaintext
    text2 = bytearray(text1)
    text2[0] = text2[0] ^ 0x01
    text2 = bytes(text2)

    cipher1 = q_ekea_high_entropy_cipher(text1, q_master_seed, mode="encrypt")
    cipher2 = q_ekea_high_entropy_cipher(text2, q_master_seed, mode="encrypt")

    ae_score = calculate_avalanche_effect(cipher1, cipher2)

    print(f"Actual Message Length: {len(text1)} bytes")
    print("Bits Changed in Plaintext: 1 (at position 0)")
    print(f"Avalanche Effect Score: {ae_score:.2f}%\n")

    if args.plot:
        qml.draw_mpl(get_quantum_seed_block)()
        plt.show()

        qml.draw_mpl(get_quantum_feedback_params)(72)
        plt.show()
