import importlib
import math
import os
import sys
import time
from collections import Counter

import nist_metrics

# Attempt cryptography import, prompt gracefully if missing
try:
    # Silence deliberate legacy algorithm warnings (3DES)
    import warnings

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    warnings.filterwarnings("ignore", category=UserWarning)
    warnings.filterwarnings("ignore", module="cryptography")
    try:
        from cryptography.utils import CryptographyDeprecationWarning

        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
    except ImportError:
        pass

except ImportError:
    print("Error: The 'cryptography' library is not installed.")
    print("Please install it using: pip install cryptography")
    sys.exit(1)

# Dynamically import the quantum script since it has hyphens
q_arx = importlib.import_module("quantum_filtered_arx")


def calculate_entropy(data):
    if not data:
        return 0
    count = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in count.values())


def avalanche_effect(c1, c2):
    if len(c1) != len(c2):
        return 0
    flipped = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(c1, c2))
    return (flipped / (len(c1) * 8)) * 100.0


def benchmark_quantum_arx(message, master_seed, rounds=100):
    print(f"[ Quantum-ARX Hybrid Cipher ] - Running {rounds} iterations...")

    total_enc = 0.0
    total_dec = 0.0
    for _ in range(rounds):
        enc_start = time.time()
        cipher = q_arx.encrypt(message, master_seed)
        total_enc += time.time() - enc_start

        dec_start = time.time()
        plain = q_arx.decrypt(cipher, master_seed)
        total_dec += time.time() - dec_start

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    assert message == plain, "Decryption failed!"

    # Plaintext Avalanche
    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    cipher2 = q_arx.encrypt(bytes(mod_msg), master_seed)
    ae = avalanche_effect(cipher, cipher2)

    # Key Avalanche
    mod_seed = master_seed ^ 1
    cipher_k2 = q_arx.encrypt(message, mod_seed)
    kae = avalanche_effect(cipher, cipher_k2)

    nist = nist_metrics.run_all_tests(cipher)
    return {
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(cipher) - len(message),
        "entropy": calculate_entropy(cipher),
        "avalanche": ae,
        "key_avalanche": kae,
        "nist_monobit": nist["Monobit"],
        "nist_block": nist["BlockFrequency"],
        "nist_runs": nist["Runs"],
    }


def benchmark_aes256_gcm(message, rounds=100):
    print(f"[ AES-256-GCM Baseline ] - Running {rounds} iterations...")
    key = os.urandom(32)
    iv = os.urandom(12)

    total_enc = 0.0
    total_dec = 0.0
    for _ in range(rounds):
        enc_start = time.time()
        cipher_obj = Cipher(
            algorithms.AES(key), modes.GCM(iv), backend=default_backend()
        )
        encryptor = cipher_obj.encryptor()
        cipher = encryptor.update(message) + encryptor.finalize()
        tag = encryptor.tag
        total_enc += time.time() - enc_start

        dec_start = time.time()
        decrypt_cipher_obj = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
        )
        decryptor = decrypt_cipher_obj.decryptor()
        plain = decryptor.update(cipher) + decryptor.finalize()
        total_dec += time.time() - dec_start

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    # GCM requires IV and tag overhead
    final_ciphertext = iv + cipher + tag

    assert message == plain, "Decryption failed!"

    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    encryptor2 = cipher_obj.encryptor()
    cipher2 = encryptor2.update(bytes(mod_msg)) + encryptor2.finalize()
    final_cipher2 = iv + cipher2 + encryptor2.tag

    ae = avalanche_effect(
        final_ciphertext[: min(len(final_ciphertext), len(final_cipher2))],
        final_cipher2[: min(len(final_ciphertext), len(final_cipher2))],
    )

    mod_key = bytearray(key)
    mod_key[0] ^= 0x01
    cipher_obj3 = Cipher(
        algorithms.AES(bytes(mod_key)), modes.GCM(iv), backend=default_backend()
    )
    encryptor3 = cipher_obj3.encryptor()
    cipher3 = encryptor3.update(message) + encryptor3.finalize()
    final_cipher3 = iv + cipher3 + encryptor3.tag

    kae = avalanche_effect(
        final_ciphertext[: min(len(final_ciphertext), len(final_cipher3))],
        final_cipher3[: min(len(final_ciphertext), len(final_cipher3))],
    )

    nist = nist_metrics.run_all_tests(final_ciphertext)
    return {
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(final_ciphertext) - len(message),
        "entropy": calculate_entropy(final_ciphertext),
        "avalanche": ae,
        "key_avalanche": kae,
        "nist_monobit": nist["Monobit"],
        "nist_block": nist["BlockFrequency"],
        "nist_runs": nist["Runs"],
    }


def benchmark_chacha20(message, rounds=100):
    print(f"[ ChaCha20 Stream Cipher ] - Running {rounds} iterations...")
    key = os.urandom(32)
    nonce = os.urandom(16)

    total_enc = 0.0
    total_dec = 0.0
    for _ in range(rounds):
        enc_start = time.time()
        cipher_obj = Cipher(
            algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()
        )
        encryptor = cipher_obj.encryptor()
        cipher = encryptor.update(message)
        total_enc += time.time() - enc_start

        dec_start = time.time()
        decrypt_cipher_obj = Cipher(
            algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend()
        )
        decryptor = decrypt_cipher_obj.decryptor()
        plain = decryptor.update(cipher)
        total_dec += time.time() - dec_start

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    final_ciphertext = nonce + cipher

    assert message == plain, "Decryption failed!"

    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    encryptor2 = cipher_obj.encryptor()
    cipher2 = encryptor2.update(bytes(mod_msg))
    final_cipher2 = nonce + cipher2

    ae = avalanche_effect(final_ciphertext, final_cipher2)

    mod_key = bytearray(key)
    mod_key[0] ^= 0x01
    cipher_obj3 = Cipher(
        algorithms.ChaCha20(bytes(mod_key), nonce), mode=None, backend=default_backend()
    )
    encryptor3 = cipher_obj3.encryptor()
    cipher3 = encryptor3.update(message)
    final_cipher3 = nonce + cipher3

    kae = avalanche_effect(final_ciphertext, final_cipher3)

    nist = nist_metrics.run_all_tests(final_ciphertext)
    return {
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(final_ciphertext) - len(message),
        "entropy": calculate_entropy(final_ciphertext),
        "avalanche": ae,
        "key_avalanche": kae,
        "nist_monobit": nist["Monobit"],
        "nist_block": nist["BlockFrequency"],
        "nist_runs": nist["Runs"],
    }


def benchmark_3des(message, rounds=100):
    print(f"[ 3DES-CBC (Legacy Baseline) ] - Running {rounds} iterations...")
    key = os.urandom(24)
    iv = os.urandom(8)

    total_enc = 0.0
    total_dec = 0.0
    for _ in range(rounds):
        enc_start = time.time()
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher_obj = Cipher(
            algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher_obj.encryptor()
        cipher = encryptor.update(padded_data) + encryptor.finalize()
        total_enc += time.time() - enc_start

        dec_start = time.time()
        decrypt_cipher_obj = Cipher(
            algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = decrypt_cipher_obj.decryptor()
        padded_plain = decryptor.update(cipher) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()
        total_dec += time.time() - dec_start

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    final_ciphertext = iv + cipher

    assert message == plain, "Decryption failed!"

    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    padder2 = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_mod = padder2.update(bytes(mod_msg)) + padder2.finalize()
    encryptor2 = cipher_obj.encryptor()
    cipher2 = encryptor2.update(padded_mod) + encryptor2.finalize()
    final_cipher2 = iv + cipher2

    ae = avalanche_effect(final_ciphertext, final_cipher2)

    mod_key = bytearray(key)
    mod_key[0] ^= 0x01
    cipher_obj3 = Cipher(
        algorithms.TripleDES(bytes(mod_key)), modes.CBC(iv), backend=default_backend()
    )
    encryptor3 = cipher_obj3.encryptor()
    cipher3 = encryptor3.update(padded_data) + encryptor3.finalize()
    final_cipher3 = iv + cipher3

    kae = avalanche_effect(
        final_ciphertext[: min(len(final_ciphertext), len(final_cipher3))],
        final_cipher3[: min(len(final_ciphertext), len(final_cipher3))],
    )

    nist = nist_metrics.run_all_tests(final_ciphertext)
    return {
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(final_ciphertext) - len(message),
        "entropy": calculate_entropy(final_ciphertext),
        "avalanche": ae,
        "key_avalanche": kae,
        "nist_monobit": nist["Monobit"],
        "nist_block": nist["BlockFrequency"],
        "nist_runs": nist["Runs"],
    }


def benchmark_aes_ecb(message, rounds=100):
    print(f"[ AES-128-ECB (Insecure Mode Demo) ] - Running {rounds} iterations...")
    key = os.urandom(16)

    total_enc = 0.0
    total_dec = 0.0
    for _ in range(rounds):
        enc_start = time.time()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher_obj = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher_obj.encryptor()
        cipher = encryptor.update(padded_data) + encryptor.finalize()
        total_enc += time.time() - enc_start

        dec_start = time.time()
        decrypt_cipher_obj = Cipher(
            algorithms.AES(key), modes.ECB(), backend=default_backend()
        )
        decryptor = decrypt_cipher_obj.decryptor()
        padded_plain = decryptor.update(cipher) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()
        total_dec += time.time() - dec_start

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    assert message == plain, "Decryption failed!"

    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    padder2 = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_mod = padder2.update(bytes(mod_msg)) + padder2.finalize()
    encryptor2 = cipher_obj.encryptor()
    cipher2 = encryptor2.update(padded_mod) + encryptor2.finalize()

    # ECB fails plain avalanche tests significantly! This expects < 1.0%
    ae = avalanche_effect(cipher, cipher2)

    mod_key = bytearray(key)
    mod_key[0] ^= 0x01
    cipher_obj3 = Cipher(
        algorithms.AES(bytes(mod_key)), modes.ECB(), backend=default_backend()
    )
    encryptor3 = cipher_obj3.encryptor()
    cipher3 = encryptor3.update(padded_data) + encryptor3.finalize()

    kae = avalanche_effect(
        cipher[: min(len(cipher), len(cipher3))],
        cipher3[: min(len(cipher), len(cipher3))],
    )

    nist = nist_metrics.run_all_tests(cipher)
    return {
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(cipher) - len(message),
        "entropy": calculate_entropy(cipher),
        "avalanche": ae,
        "key_avalanche": kae,
        "nist_monobit": nist["Monobit"],
        "nist_block": nist["BlockFrequency"],
        "nist_runs": nist["Runs"],
    }


def run_statistical_nist_benchmark(msg_len=10000, iterations=50):
    """
    Industry-standard stability benchmark.
    Runs NIST tests over multiple unique keys/data and reports the Pass Rate (%).
    Threshold p >= 0.01 per NIST SP 800-22.
    """
    print(f"\n[ STATISTICAL PASS RATE BENCHMARK ] - Iterations: {iterations}")
    print("Testing long-term consistency against random seeds. Please wait...")

    # Algorithms to test
    ciphers = {
        "Q-ARX": "quantum",
        "AES-GCM": "aes",
        "ChaCha": "chacha",
        "3DES": "3des",
        "AES-ECB": "ecb",
    }

    # Pass counters and p-value sums
    passes = {name: {"Monobit": 0, "Block": 0, "Runs": 0} for name in ciphers}
    sums = {name: {"Monobit": 0.0, "Block": 0.0, "Runs": 0.0} for name in ciphers}

    for i in range(iterations):
        if (i + 1) % 10 == 0:
            print(f"  Iteration {i+1}/{iterations}...")

        msg = os.urandom(msg_len)
        seed = int.from_bytes(os.urandom(32), byteorder="big")
        aes_key = os.urandom(32)
        des_key = os.urandom(16)

        # 1. Q-ARX
        c_q = q_arx.encrypt(msg, seed)
        n_q = nist_metrics.run_all_tests(c_q)
        sums["Q-ARX"]["Monobit"] += n_q["Monobit"]
        sums["Q-ARX"]["Block"] += n_q["BlockFrequency"]
        sums["Q-ARX"]["Runs"] += n_q["Runs"]
        if n_q["Monobit"] >= 0.01: passes["Q-ARX"]["Monobit"] += 1
        if n_q["BlockFrequency"] >= 0.01: passes["Q-ARX"]["Block"] += 1
        if n_q["Runs"] >= 0.01: passes["Q-ARX"]["Runs"] += 1

        # 2. AES-GCM
        nonce = os.urandom(12)
        cipher_obj = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher_obj.encryptor()
        c_aes = encryptor.update(msg) + encryptor.finalize()
        n_a = nist_metrics.run_all_tests(c_aes)
        sums["AES-GCM"]["Monobit"] += n_a["Monobit"]
        sums["AES-GCM"]["Block"] += n_a["BlockFrequency"]
        sums["AES-GCM"]["Runs"] += n_a["Runs"]
        if n_a["Monobit"] >= 0.01: passes["AES-GCM"]["Monobit"] += 1
        if n_a["BlockFrequency"] >= 0.01: passes["AES-GCM"]["Block"] += 1
        if n_a["Runs"] >= 0.01: passes["AES-GCM"]["Runs"] += 1

        # 3. ChaCha20
        nonce_c = os.urandom(16)
        algorithm = algorithms.ChaCha20(aes_key, nonce_c)
        cipher_obj_c = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor_c = cipher_obj_c.encryptor()
        c_cha = encryptor_c.update(msg)
        n_c = nist_metrics.run_all_tests(c_cha)
        sums["ChaCha"]["Monobit"] += n_c["Monobit"]
        sums["ChaCha"]["Block"] += n_c["BlockFrequency"]
        sums["ChaCha"]["Runs"] += n_c["Runs"]
        if n_c["Monobit"] >= 0.01: passes["ChaCha"]["Monobit"] += 1
        if n_c["BlockFrequency"] >= 0.01: passes["ChaCha"]["Block"] += 1
        if n_c["Runs"] >= 0.01: passes["ChaCha"]["Runs"] += 1

        # 4. 3DES
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_msg = padder.update(msg) + padder.finalize()
        cipher_obj_d = Cipher(algorithms.TripleDES(des_key), modes.CBC(os.urandom(8)), backend=default_backend())
        encryptor_d = cipher_obj_d.encryptor()
        c_des = encryptor_d.update(padded_msg) + encryptor_d.finalize()
        n_d = nist_metrics.run_all_tests(c_des)
        sums["3DES"]["Monobit"] += n_d["Monobit"]
        sums["3DES"]["Block"] += n_d["BlockFrequency"]
        sums["3DES"]["Runs"] += n_d["Runs"]
        if n_d["Monobit"] >= 0.01: passes["3DES"]["Monobit"] += 1
        if n_d["BlockFrequency"] >= 0.01: passes["3DES"]["Block"] += 1
        if n_d["Runs"] >= 0.01: passes["3DES"]["Runs"] += 1

        # 5. ECB
        padder_e = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_msg_e = padder_e.update(msg) + padder_e.finalize()
        cipher_obj_e = Cipher(algorithms.AES(aes_key[:16]), modes.ECB(), backend=default_backend())
        encryptor_e = cipher_obj_e.encryptor()
        c_ecb = encryptor_e.update(padded_msg_e) + encryptor_e.finalize()
        n_e = nist_metrics.run_all_tests(c_ecb)
        sums["AES-ECB"]["Monobit"] += n_e["Monobit"]
        sums["AES-ECB"]["Block"] += n_e["BlockFrequency"]
        sums["AES-ECB"]["Runs"] += n_e["Runs"]
        if n_e["Monobit"] >= 0.01: passes["AES-ECB"]["Monobit"] += 1
        if n_e["BlockFrequency"] >= 0.01: passes["AES-ECB"]["Block"] += 1
        if n_e["Runs"] >= 0.01: passes["AES-ECB"]["Runs"] += 1

    print("\n" + "="*80)
    print("      NIST STATISTICAL PERFORMANCE (Pass Rate % | Avg P-Value)")
    print("="*80)
    print(f"{'Algorithm':<12} | {'Monobit':<18} | {'Block':<18} | {'Runs':<18}")
    print("-" * 80)
    for name in ciphers:
        m_pr = (passes[name]["Monobit"] / iterations) * 100
        b_pr = (passes[name]["Block"] / iterations) * 100
        r_pr = (passes[name]["Runs"] / iterations) * 100
        
        m_avg = sums[name]["Monobit"] / iterations
        b_avg = sums[name]["Block"] / iterations
        r_avg = sums[name]["Runs"] / iterations
        
        print(f"{name:<12} | {m_pr:>5.1f}% ({m_avg:4.2f}) | {b_pr:>5.1f}% ({b_avg:4.2f}) | {r_pr:>5.1f}% ({r_avg:4.2f})")
    print("="*80)
    print("Note: Industry standard (NIST) pass rate typically >= 98-99%.")



if __name__ == "__main__":
    # Number of averaging rounds
    test_rounds = 20

    MSG_LEN = 10000
    print(f"Creating a standardized benchmark using Plaintext Length: {MSG_LEN} Bytes.")
    print(
        f"Executing {test_rounds} rounds for perfectly smoothed OS timing averages. (This will take a few minutes for ARX!)"
    )
    message = os.urandom(MSG_LEN)

    # 256-bit Seed equivalent for Quantum-ARX
    master_seed = int.from_bytes(os.urandom(32), byteorder="big")

    r_arx = benchmark_quantum_arx(message, master_seed, rounds=test_rounds)
    r_aes = benchmark_aes256_gcm(message, rounds=test_rounds)
    r_cha = benchmark_chacha20(message, rounds=test_rounds)
    r_des = benchmark_3des(message, rounds=test_rounds)
    r_ecb = benchmark_aes_ecb(message, rounds=test_rounds)

    print(
        "\n================================== BENCHMARK RESULTS =================================="
    )
    print(
        f"{'Metric':<15} | {'Q-ARX':<10} | {'AES-GCM':<10} | {'ChaCha':<8} | {'3DES':<8} | {'AES-ECB':<10}"
    )
    print("-" * 87)
    print(
        f"{'Enc Time (s)':<15} | {r_arx['enc_time']:<10.4f} | {r_aes['enc_time']:<10.4f} | {r_cha['enc_time']:<8.4f} | {r_des['enc_time']:<8.4f} | {r_ecb['enc_time']:<10.4f}"
    )
    print(
        f"{'Dec Time (s)':<15} | {r_arx['dec_time']:<10.4f} | {r_aes['dec_time']:<10.4f} | {r_cha['dec_time']:<8.4f} | {r_des['dec_time']:<8.4f} | {r_ecb['dec_time']:<10.4f}"
    )
    print(
        f"{'Overhead (B)':<15} | {r_arx['len_change']:<10} | {r_aes['len_change']:<10} | {r_cha['len_change']:<8} | {r_des['len_change']:<8} | {r_ecb['len_change']:<10}"
    )
    print(
        f"{'Entropy':<15} | {r_arx['entropy']:<10.4f} | {r_aes['entropy']:<10.4f} | {r_cha['entropy']:<8.4f} | {r_des['entropy']:<8.4f} | {r_ecb['entropy']:<10.4f}"
    )
    print(
        f"{'Plain Aval (%)':<15} | {r_arx['avalanche']:<10.2f} | {r_aes['avalanche']:<10.2f} | {r_cha['avalanche']:<8.2f} | {r_des['avalanche']:<8.2f} | {r_ecb['avalanche']:<10.2f}"
    )
    print(
        f"{'Key Aval (%)':<15} | {r_arx['key_avalanche']:<10.2f} | {r_aes['key_avalanche']:<10.2f} | {r_cha['key_avalanche']:<8.2f} | {r_des['key_avalanche']:<8.2f} | {r_ecb['key_avalanche']:<10.2f}"
    )
    print(
        f"{'NIST Monobit':<15} | {r_arx['nist_monobit']:<10.4f} | {r_aes['nist_monobit']:<10.4f} | {r_cha['nist_monobit']:<8.4f} | {r_des['nist_monobit']:<8.4f} | {r_ecb['nist_monobit']:<10.4f}"
    )
    print(
        f"{'NIST Block Freq':<15} | {r_arx['nist_block']:<10.4f} | {r_aes['nist_block']:<10.4f} | {r_cha['nist_block']:<8.4f} | {r_des['nist_block']:<8.4f} | {r_ecb['nist_block']:<10.4f}"
    )
    print(
        f"{'NIST Runs':<15} | {r_arx['nist_runs']:<10.4f} | {r_aes['nist_runs']:<10.4f} | {r_cha['nist_runs']:<8.4f} | {r_des['nist_runs']:<8.4f} | {r_ecb['nist_runs']:<10.4f}"
    )
    print(
        "======================================================================================="
    )

    # NEW: Run Statistical Mode
    run_statistical_nist_benchmark(msg_len=MSG_LEN, iterations= test_rounds if test_rounds > 20 else 50)
