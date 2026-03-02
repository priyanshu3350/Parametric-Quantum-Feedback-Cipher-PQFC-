import numpy as np
import pennylane as qml

# ==========================================
# Quantum Layer (PennyLane Implementation)
# ==========================================

# Initialize a 4-qubit quantum simulator device
dev = qml.device("default.qubit", wires=4)


@qml.qnode(dev)
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


def generate_qpp_sbox(z_expects):
    """
    Generates a dynamic Quantum Permutation Pad (QPP) / S-Box.
    """
    # Extract seed, strip types, and strictly bound it to 32-bit max for RandomState
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

        # Cast the S-Box output to a standard Python int to prevent NumPy 2.0 OverflowErrors
        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        modular_addition = (p + k_i) % 256
        rotated = rotl8(modular_addition, r_i)
        c_i_byte = rotated ^ prev_c

        ciphertext.append(c_i_byte)

        prev_c = c_i_byte
        x_n = (a_i * x_n + c_i) % (2**32)

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

        # Cast the S-Box output to a standard Python int
        k_i = int(sbox[raw_lcg_byte])

        r_i = int(float(abs(z_expects[3])) * 7)

        un_xor = c ^ prev_c
        un_rot = rotr8(un_xor, r_i)
        p = (un_rot - k_i) % 256

        plaintext.append(p)

        prev_c = c
        x_n = (a_i * x_n + c_i) % (2**32)

    return plaintext


# ==========================================
# Execution and Verification
# ==========================================
if __name__ == "__main__":
    shared_master_seed = 0x9A4F8B3C

    message = "PennyLane Quantum-Filtered ARX".encode()

    print(f"Original Plaintext: {message}")

    encrypted_data = encrypt(message, shared_master_seed)
    print(f"Ciphertext (Hex):   {encrypted_data.hex()}")

    decrypted_data = decrypt(encrypted_data, shared_master_seed)
    print(f"Decrypted Data:     {decrypted_data.decode('utf-8', errors='ignore')}")

    assert message == decrypted_data, "Decryption failed!"
    print("\nSuccess: Quantum-classical feedback loop reversed flawlessly.")
