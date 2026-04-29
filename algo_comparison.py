"""
Quantum-ARX Cipher Benchmark Suite
====================================
Registry-based comparison of 6 cipher implementations against
8 NIST SP 800-22 randomness tests.

Ciphers:
  1. Quantum-Filtered ARX (PennyLane)
  2. Quantum-Filtered ARX Bitops (optimised)
  3. AES-256-GCM
  4. ChaCha20
  5. 3DES-CBC
  6. AES-128-ECB

Outputs:
  - Formatted console table
  - Matplotlib comparison charts  → images/
  - CSV export                    → images/benchmark_results.csv
"""

import csv
import importlib
import math
import os
import sys
import time
from collections import Counter

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — safe for headless servers
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

import nist_metrics

# ============================================================
# Suppress legacy-algorithm warnings (3DES deprecation, etc.)
# ============================================================
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="cryptography")
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
except ImportError:
    pass

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: The 'cryptography' library is not installed.")
    print("Please install it using: pip install cryptography")
    sys.exit(1)

# Dynamic imports for the two quantum ARX variants
q_arx = importlib.import_module("quantum_filtered_arx")
q_arx_bitops = importlib.import_module("quantum_filtered_arx_bitops")


# ============================================================
# Shared Helpers
# ============================================================

def calculate_entropy(data):
    """Shannon entropy in bits per byte."""
    if not data:
        return 0
    count = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in count.values())


def avalanche_effect(c1, c2):
    """Percentage of flipped bits between two equal-length byte sequences."""
    min_len = min(len(c1), len(c2))
    if min_len == 0:
        return 0
    flipped = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(c1[:min_len], c2[:min_len]))
    return (flipped / (min_len * 8)) * 100.0


# ============================================================
# Cipher Registry
# ============================================================
# Each entry defines:
#   name       – display label
#   setup()    – returns an opaque context dict (key, iv, etc.)
#   encrypt(msg, ctx) – returns ciphertext bytes
#   decrypt(ct, ctx)  – returns plaintext bytes
#   mutate_key(ctx)   – returns a NEW context with 1-bit key change
#   has_overhead      – True if ciphertext includes IV/tag overhead
# ============================================================

def _make_quantum_arx_ctx(master_seed):
    return {"seed": master_seed}


def _make_quantum_arx_mutated(ctx):
    return {"seed": ctx["seed"] ^ 1}


def _make_aes_gcm_ctx(_=None):
    key = os.urandom(32)
    iv = os.urandom(12)
    return {"key": key, "iv": iv}


def _make_chacha_ctx(_=None):
    key = os.urandom(32)
    nonce = os.urandom(16)
    return {"key": key, "nonce": nonce}


def _make_3des_ctx(_=None):
    key = os.urandom(24)   # Fixed: was 16, must be 24 for full 3-key 3DES
    iv = os.urandom(8)
    return {"key": key, "iv": iv}


def _make_aes_ecb_ctx(_=None):
    key = os.urandom(16)
    return {"key": key}


# ---- Encrypt / Decrypt closures ----

def _enc_qarx(msg, ctx):
    return bytes(q_arx.encrypt(msg, ctx["seed"]))

def _dec_qarx(ct, ctx):
    return bytes(q_arx.decrypt(ct, ctx["seed"]))

def _enc_qarx_bitops(msg, ctx):
    return bytes(q_arx_bitops.encrypt(msg, ctx["seed"]))

def _dec_qarx_bitops(ct, ctx):
    return bytes(q_arx_bitops.decrypt(ct, ctx["seed"]))


def _enc_aes_gcm(msg, ctx):
    cipher_obj = Cipher(algorithms.AES(ctx["key"]), modes.GCM(ctx["iv"]),
                        backend=default_backend())
    enc = cipher_obj.encryptor()
    ct = enc.update(msg) + enc.finalize()
    # Store tag for later decryption / overhead calc
    ctx["_tag"] = enc.tag
    ctx["_raw_ct"] = ct
    return ctx["iv"] + ct + enc.tag  # full wire format


def _dec_aes_gcm(ct_full, ctx):
    iv = ct_full[:12]
    tag = ct_full[-16:]
    ct = ct_full[12:-16]
    cipher_obj = Cipher(algorithms.AES(ctx["key"]), modes.GCM(iv, tag),
                        backend=default_backend())
    dec = cipher_obj.decryptor()
    return dec.update(ct) + dec.finalize()


def _enc_chacha(msg, ctx):
    cipher_obj = Cipher(algorithms.ChaCha20(ctx["key"], ctx["nonce"]),
                        mode=None, backend=default_backend())
    enc = cipher_obj.encryptor()
    ct = enc.update(msg)
    return ctx["nonce"] + ct


def _dec_chacha(ct_full, ctx):
    nonce = ct_full[:16]
    ct = ct_full[16:]
    cipher_obj = Cipher(algorithms.ChaCha20(ctx["key"], nonce),
                        mode=None, backend=default_backend())
    dec = cipher_obj.decryptor()
    return dec.update(ct)


def _enc_3des(msg, ctx):
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded = padder.update(msg) + padder.finalize()
    cipher_obj = Cipher(algorithms.TripleDES(ctx["key"]), modes.CBC(ctx["iv"]),
                        backend=default_backend())
    enc = cipher_obj.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return ctx["iv"] + ct


def _dec_3des(ct_full, ctx):
    iv = ct_full[:8]
    ct = ct_full[8:]
    cipher_obj = Cipher(algorithms.TripleDES(ctx["key"]), modes.CBC(iv),
                        backend=default_backend())
    dec = cipher_obj.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _enc_aes_ecb(msg, ctx):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(msg) + padder.finalize()
    cipher_obj = Cipher(algorithms.AES(ctx["key"]), modes.ECB(),
                        backend=default_backend())
    enc = cipher_obj.encryptor()
    return enc.update(padded) + enc.finalize()


def _dec_aes_ecb(ct, ctx):
    cipher_obj = Cipher(algorithms.AES(ctx["key"]), modes.ECB(),
                        backend=default_backend())
    dec = cipher_obj.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _mutate_bytes_key(ctx, field="key"):
    """Return a new context with bit 0 of the key flipped."""
    new_ctx = dict(ctx)
    mod_key = bytearray(ctx[field])
    mod_key[0] ^= 0x01
    new_ctx[field] = bytes(mod_key)
    return new_ctx


CIPHER_REGISTRY = [
    {
        "name": "Q-ARX",
        "setup": lambda seed: _make_quantum_arx_ctx(seed),
        "encrypt": _enc_qarx,
        "decrypt": _dec_qarx,
        "mutate_key": _make_quantum_arx_mutated,
        "needs_seed": True,
    },
    {
        "name": "Q-ARX Bitops",
        "setup": lambda seed: _make_quantum_arx_ctx(seed),
        "encrypt": _enc_qarx_bitops,
        "decrypt": _dec_qarx_bitops,
        "mutate_key": _make_quantum_arx_mutated,
        "needs_seed": True,
    },
    {
        "name": "AES-256-GCM",
        "setup": lambda _=None: _make_aes_gcm_ctx(),
        "encrypt": _enc_aes_gcm,
        "decrypt": _dec_aes_gcm,
        "mutate_key": lambda ctx: _mutate_bytes_key(ctx, "key"),
        "needs_seed": False,
    },
    {
        "name": "ChaCha20",
        "setup": lambda _=None: _make_chacha_ctx(),
        "encrypt": _enc_chacha,
        "decrypt": _dec_chacha,
        "mutate_key": lambda ctx: _mutate_bytes_key(ctx, "key"),
        "needs_seed": False,
    },
    {
        "name": "3DES-CBC",
        "setup": lambda _=None: _make_3des_ctx(),
        "encrypt": _enc_3des,
        "decrypt": _dec_3des,
        "mutate_key": lambda ctx: _mutate_bytes_key(ctx, "key"),
        "needs_seed": False,
    },
    {
        "name": "AES-128-ECB",
        "setup": lambda _=None: _make_aes_ecb_ctx(),
        "encrypt": _enc_aes_ecb,
        "decrypt": _dec_aes_ecb,
        "mutate_key": lambda ctx: _mutate_bytes_key(ctx, "key"),
        "needs_seed": False,
    },
]


# ============================================================
# Generic Benchmark Engine
# ============================================================

def run_benchmark(cipher, message, master_seed, rounds=20):
    """
    Run a full benchmark for one cipher entry from the registry.
    Returns a dict of all metrics.
    """
    name = cipher["name"]
    print(f"[ {name} ] — Running {rounds} iterations...")

    ctx = cipher["setup"](master_seed) if cipher.get("needs_seed") else cipher["setup"]()

    # --- Timing (perf_counter for sub-μs precision) ---
    total_enc = 0.0
    total_dec = 0.0
    ciphertext = None
    plaintext = None

    for _ in range(rounds):
        t0 = time.perf_counter()
        ciphertext = cipher["encrypt"](message, ctx)
        total_enc += time.perf_counter() - t0

        t1 = time.perf_counter()
        plaintext = cipher["decrypt"](ciphertext, ctx)
        total_dec += time.perf_counter() - t1

    enc_time = total_enc / rounds
    dec_time = total_dec / rounds

    # --- Correctness ---
    assert plaintext == message, f"{name}: Decryption verification FAILED!"

    # --- Plaintext Avalanche ---
    mod_msg = bytearray(message)
    mod_msg[0] ^= 0x01
    cipher2 = cipher["encrypt"](bytes(mod_msg), ctx)
    ae = avalanche_effect(ciphertext, cipher2)

    # --- Key Avalanche ---
    ctx_mutated = cipher["mutate_key"](ctx)
    cipher3 = cipher["encrypt"](message, ctx_mutated)
    kae = avalanche_effect(ciphertext, cipher3)

    # --- NIST Tests (all 8) ---
    nist = nist_metrics.run_all_tests(ciphertext)

    return {
        "name": name,
        "enc_time": enc_time,
        "dec_time": dec_time,
        "len_change": len(ciphertext) - len(message),
        "entropy": calculate_entropy(ciphertext),
        "avalanche": ae,
        "key_avalanche": kae,
        **{f"nist_{k}": v for k, v in nist.items()},
    }


# ============================================================
# Statistical NIST Pass-Rate Benchmark
# ============================================================

NIST_TEST_NAMES = [
    "Monobit", "BlockFrequency", "Runs", "LongestRun",
    "CumulativeSums", "ApproximateEntropy", "Serial", "Spectral",
]


def run_statistical_nist_benchmark(msg_len=10000, iterations=50):
    """
    Industry-standard stability benchmark.
    Runs all 8 NIST tests over multiple unique keys/data and reports Pass Rate (%).
    Threshold p >= 0.01 per NIST SP 800-22.
    """
    print(f"\n{'=' * 100}")
    print(f"  STATISTICAL NIST PASS-RATE BENCHMARK — {iterations} iterations × {len(CIPHER_REGISTRY)} ciphers × {len(NIST_TEST_NAMES)} tests")
    print(f"{'=' * 100}")
    print("Testing long-term consistency against random seeds. Please wait...\n")

    cipher_names = [c["name"] for c in CIPHER_REGISTRY]
    passes = {n: {t: 0 for t in NIST_TEST_NAMES} for n in cipher_names}
    sums = {n: {t: 0.0 for t in NIST_TEST_NAMES} for n in cipher_names}

    for i in range(iterations):
        if (i + 1) % 10 == 0:
            print(f"  Iteration {i + 1}/{iterations}...")

        msg = os.urandom(msg_len)
        seed = int.from_bytes(os.urandom(32), byteorder="big")

        for cipher in CIPHER_REGISTRY:
            name = cipher["name"]
            ctx = cipher["setup"](seed) if cipher.get("needs_seed") else cipher["setup"]()
            ct = cipher["encrypt"](msg, ctx)

            nist_results = nist_metrics.run_all_tests(ct)

            for test_name in NIST_TEST_NAMES:
                p = nist_results[test_name]
                sums[name][test_name] += p
                if p >= 0.01:
                    passes[name][test_name] += 1

    # ---- Pretty-print results ----
    col_w = 20
    header = f"{'Algorithm':<16}"
    for t in NIST_TEST_NAMES:
        header += f" | {t:^{col_w}}"
    print("\n" + "=" * len(header))
    print("  NIST STATISTICAL PERFORMANCE  (Pass Rate %  |  Avg P-Value)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for name in cipher_names:
        row = f"{name:<16}"
        for t in NIST_TEST_NAMES:
            pr = (passes[name][t] / iterations) * 100
            avg = sums[name][t] / iterations
            row += f" | {pr:>5.1f}% ({avg:.2f})     "
        print(row)

    print("=" * len(header))
    print("Note: Industry standard (NIST) pass rate typically >= 98-99%.\n")


# ============================================================
# Matplotlib Charts
# ============================================================

# Curated colour palette — one per cipher
PALETTE = ["#6366f1", "#8b5cf6", "#06b6d4", "#22c55e", "#f59e0b", "#ef4444"]


def _save_fig(fig, filename):
    """Save figure to images/ directory."""
    os.makedirs("images", exist_ok=True)
    path = os.path.join("images", filename)
    fig.savefig(path, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  ✓ Saved {path}")


def _style_ax(ax, title, ylabel=""):
    """Apply a consistent dark theme to an axis."""
    ax.set_facecolor("#0f172a")
    ax.set_title(title, fontsize=14, fontweight="bold", color="white", pad=12)
    ax.set_ylabel(ylabel, color="white")
    ax.tick_params(colors="white", labelsize=9)
    for spine in ax.spines.values():
        spine.set_color("#334155")


def plot_timing(results):
    """Bar chart comparing encryption and decryption times."""
    names = [r["name"] for r in results]
    enc = [r["enc_time"] * 1000 for r in results]  # ms
    dec = [r["dec_time"] * 1000 for r in results]

    x = np.arange(len(names))
    w = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.set_facecolor("#020617")

    bars1 = ax.bar(x - w / 2, enc, w, label="Encryption", color=PALETTE[:len(names)], edgecolor="white", linewidth=0.5)
    bars2 = ax.bar(x + w / 2, dec, w, label="Decryption", color=PALETTE[:len(names)], alpha=0.6, edgecolor="white", linewidth=0.5)

    _style_ax(ax, "Encryption / Decryption Time Comparison", ylabel="Time (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right", color="white")
    ax.legend(facecolor="#1e293b", edgecolor="#475569", labelcolor="white")
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())

    _save_fig(fig, "benchmark_timing.png")


def plot_entropy(results):
    """Bar chart comparing Shannon entropy."""
    names = [r["name"] for r in results]
    ent = [r["entropy"] for r in results]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.set_facecolor("#020617")

    ax.bar(names, ent, color=PALETTE[:len(names)], edgecolor="white", linewidth=0.5)
    ax.axhline(y=8.0, color="#ef4444", linestyle="--", linewidth=1, label="Ideal (8.0)")
    _style_ax(ax, "Shannon Entropy Comparison (bits/byte)", ylabel="Entropy")
    ax.set_ylim(7.0, 8.1)
    ax.legend(facecolor="#1e293b", edgecolor="#475569", labelcolor="white")
    plt.xticks(rotation=20, ha="right")

    _save_fig(fig, "benchmark_entropy.png")


def plot_avalanche(results):
    """Grouped bar chart for plaintext and key avalanche effects."""
    names = [r["name"] for r in results]
    p_ae = [r["avalanche"] for r in results]
    k_ae = [r["key_avalanche"] for r in results]

    x = np.arange(len(names))
    w = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.set_facecolor("#020617")

    ax.bar(x - w / 2, p_ae, w, label="Plaintext Avalanche", color="#06b6d4", edgecolor="white", linewidth=0.5)
    ax.bar(x + w / 2, k_ae, w, label="Key Avalanche", color="#8b5cf6", edgecolor="white", linewidth=0.5)
    ax.axhline(y=50.0, color="#22c55e", linestyle="--", linewidth=1, label="Ideal (50%)")

    _style_ax(ax, "Avalanche Effect Comparison", ylabel="Flipped Bits (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right", color="white")
    ax.legend(facecolor="#1e293b", edgecolor="#475569", labelcolor="white")

    _save_fig(fig, "benchmark_avalanche.png")


def plot_nist_heatmap(results):
    """Heatmap of all 8 NIST p-values across all ciphers."""
    names = [r["name"] for r in results]
    matrix = []
    for r in results:
        row = [r.get(f"nist_{t}", 0.0) for t in NIST_TEST_NAMES]
        matrix.append(row)

    data = np.array(matrix)

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.set_facecolor("#020617")

    cmap = plt.cm.RdYlGn
    im = ax.imshow(data, cmap=cmap, aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(np.arange(len(NIST_TEST_NAMES)))
    ax.set_xticklabels(NIST_TEST_NAMES, rotation=35, ha="right", fontsize=9, color="white")
    ax.set_yticks(np.arange(len(names)))
    ax.set_yticklabels(names, fontsize=10, color="white")

    # Annotate cells
    for i in range(len(names)):
        for j in range(len(NIST_TEST_NAMES)):
            val = data[i, j]
            colour = "black" if val > 0.5 else "white"
            ax.text(j, i, f"{val:.3f}", ha="center", va="center",
                    fontsize=8, color=colour, fontweight="bold")

    ax.set_title("NIST SP 800-22 P-Value Heatmap", fontsize=14,
                 fontweight="bold", color="white", pad=14)
    for spine in ax.spines.values():
        spine.set_color("#334155")

    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.04)
    cbar.ax.tick_params(colors="white")
    cbar.set_label("P-Value", color="white")

    _save_fig(fig, "benchmark_nist_heatmap.png")


# ============================================================
# CSV Export
# ============================================================

def export_csv(results, path="images/benchmark_results.csv"):
    """Write all benchmark results to a CSV file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not results:
        return

    fieldnames = list(results[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"  ✓ Saved {path}")


# ============================================================
# Console Report
# ============================================================

def print_console_report(results):
    """Pretty-print the full results table to stdout."""
    names = [r["name"] for r in results]
    col_w = max(len(n) for n in names) + 2

    # Header
    header = f"{'Metric':<22}"
    for r in results:
        header += f" | {r['name']:^{col_w}}"
    sep = "-" * len(header)

    print(f"\n{'=' * len(header)}")
    print("  COMPREHENSIVE BENCHMARK RESULTS")
    print(f"{'=' * len(header)}")
    print(header)
    print(sep)

    # Rows
    metrics = [
        ("Enc Time (s)",   "enc_time",      ".6f"),
        ("Dec Time (s)",   "dec_time",      ".6f"),
        ("Overhead (B)",   "len_change",    "d"),
        ("Entropy",        "entropy",       ".4f"),
        ("Plain Aval (%)", "avalanche",     ".2f"),
        ("Key Aval (%)",   "key_avalanche", ".2f"),
    ]

    for label, key, fmt in metrics:
        row = f"{label:<22}"
        for r in results:
            val = r[key]
            row += f" | {format(val, fmt):^{col_w}}"
        print(row)

    print(sep)
    print(f"{'NIST Tests (p-value)':<22}")
    print(sep)

    for t in NIST_TEST_NAMES:
        row = f"  {t:<20}"
        for r in results:
            val = r.get(f"nist_{t}", 0.0)
            status = "✓" if val >= 0.01 else "✗"
            row += f" | {val:>{col_w - 4}.4f} {status} "
        print(row)

    print(f"{'=' * len(header)}\n")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    # --- Configuration ---
    test_rounds = 20
    MSG_LEN = 10000

    print(f"Standardised benchmark: {MSG_LEN:,} byte plaintext × {test_rounds} rounds per cipher.\n")

    message = os.urandom(MSG_LEN)
    master_seed = int.from_bytes(os.urandom(32), byteorder="big")

    # --- Run all benchmarks ---
    all_results = []
    for cipher in CIPHER_REGISTRY:
        result = run_benchmark(cipher, message, master_seed, rounds=test_rounds)
        all_results.append(result)

    # --- Console report ---
    print_console_report(all_results)

    # --- Charts ---
    print("Generating charts...")
    plot_timing(all_results)
    plot_entropy(all_results)
    plot_avalanche(all_results)
    plot_nist_heatmap(all_results)

    # --- CSV ---
    print("Exporting CSV...")
    export_csv(all_results)

    # --- Statistical NIST benchmark ---
    run_statistical_nist_benchmark(
        msg_len=MSG_LEN,
        iterations=max(test_rounds, 50),
    )
