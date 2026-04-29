"""
NIST SP 800-22 Statistical Test Suite
======================================
Implements 8 core randomness tests from the NIST standard.
Each test returns a p-value; p >= 0.01 indicates the sequence
passes at 99% confidence.

Tests:
  1. Frequency (Monobit)
  2. Frequency Test within a Block
  3. Runs Test
  4. Longest Run of Ones in a Block
  5. Cumulative Sums (Forward + Reverse, returns minimum)
  6. Approximate Entropy
  7. Serial Test
  8. Discrete Fourier Transform (Spectral)
"""

import math

import numpy as np

try:
    from scipy.special import gammaincc, erfc as scipy_erfc
except ImportError:
    gammaincc = None
    scipy_erfc = None


# ====================================================================
# Utility
# ====================================================================

def bytes_to_bits(data):
    """Converts a bytes-like object to a string of '0' and '1's."""
    if isinstance(data, str):
        # Assume it's already a binary string if it only contains 0 and 1
        if set(data).issubset({'0', '1'}):
            return data
    return "".join(format(byte, '08b') for byte in data)


def _bits_to_int_array(bits):
    """Convert a bit-string to a numpy array of ±1 values (+1 for '1', -1 for '0')."""
    return np.array([1 if b == '1' else -1 for b in bits], dtype=np.float64)


# ====================================================================
# Test 1: Frequency (Monobit) Test
# ====================================================================

def monobit_test(data):
    """
    Frequency (Monobit) Test from NIST SP 800-22.
    Tests if the proportion of zeroes and ones is close to 0.5.
    Returns the p-value.
    """
    bits = bytes_to_bits(data)
    n = len(bits)
    if n == 0:
        return 0.0

    # Convert '0' to -1 and '1' to +1, and sum them
    S = sum(1 if b == '1' else -1 for b in bits)

    s_obs = abs(S) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))

    return p_value


# ====================================================================
# Test 2: Frequency Test within a Block
# ====================================================================

def block_frequency_test(data, M=128):
    """
    Frequency Test within a Block from NIST SP 800-22.
    Tests if the proportion of ones within M-bit blocks is close to 0.5.
    M: Length of each block.
    Returns the p-value.
    """
    if gammaincc is None:
        print("Warning: scipy is required for the Block Frequency Test.")
        return 0.0

    bits = bytes_to_bits(data)
    n = len(bits)
    if n == 0:
        return 0.0

    N = n // M
    if N == 0:
        return 0.0  # Not enough data for one block

    chi_square_obs = 0.0
    for i in range(N):
        block = bits[i*M : (i+1)*M]
        pi_i = block.count('1') / M
        chi_square_obs += (pi_i - 0.5) ** 2

    chi_square_obs *= 4 * M

    # gammaincc is the regularized upper incomplete gamma function
    p_value = gammaincc(N / 2, chi_square_obs / 2)
    return p_value


# ====================================================================
# Test 3: Runs Test
# ====================================================================

def runs_test(data):
    """
    Runs Test from NIST SP 800-22.
    Tests the total number of runs in the sequence.
    Returns the p-value.
    """
    bits = bytes_to_bits(data)
    n = len(bits)
    if n == 0:
        return 0.0

    pi = bits.count('1') / n

    # Pre-test if the frequency of ones is close enough to 0.5
    tau = 2 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return 0.0

    v_n_obs = 1
    for i in range(n - 1):
        if bits[i] != bits[i+1]:
            v_n_obs += 1

    num = abs(v_n_obs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)

    if den == 0:
        return 0.0

    p_value = math.erfc(num / den)
    return p_value


# ====================================================================
# Test 4: Longest Run of Ones in a Block
# ====================================================================

def longest_run_of_ones_test(data):
    """
    Longest Run of Ones in a Block — NIST SP 800-22.
    Detects abnormal clustering of '1' bits within fixed-size blocks.
    Returns the p-value.
    """
    if gammaincc is None:
        print("Warning: scipy is required for the Longest Run of Ones Test.")
        return 0.0

    bits = bytes_to_bits(data)
    n = len(bits)

    # NIST defines block size (M), expected distribution (K+1 categories),
    # and chi-square probabilities based on sequence length.
    if n < 128:
        return 0.0  # Not enough data
    elif n < 6272:
        M, K = 8, 3
        v_values = [1, 2, 3, 4]  # category boundaries
        pi = [0.2148, 0.3672, 0.2305, 0.1875]
    elif n < 750000:
        M, K = 128, 5
        v_values = [4, 5, 6, 7, 8, 9]
        pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    else:
        M, K = 10000, 6
        v_values = [10, 11, 12, 13, 14, 15, 16]
        pi = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]

    N = n // M  # Number of blocks
    if N == 0:
        return 0.0

    # Count the longest run in each block and categorise
    freq = [0] * (K + 1)
    for i in range(N):
        block = bits[i * M: (i + 1) * M]

        # Find longest run of ones
        max_run = 0
        current_run = 0
        for b in block:
            if b == '1':
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 0

        # Categorise
        if max_run <= v_values[0]:
            freq[0] += 1
        elif max_run >= v_values[-1]:
            freq[K] += 1
        else:
            for j in range(1, K):
                if max_run == v_values[j]:
                    freq[j] += 1
                    break

    # Chi-square statistic
    chi_sq = sum(((freq[i] - N * pi[i]) ** 2) / (N * pi[i])
                 for i in range(K + 1) if N * pi[i] > 0)

    p_value = gammaincc(K / 2.0, chi_sq / 2.0)
    return p_value


# ====================================================================
# Test 5: Cumulative Sums Test
# ====================================================================

def cumulative_sums_test(data):
    """
    Cumulative Sums (Cusum) Test — NIST SP 800-22.
    Detects whether the cumulative sum of ±1 partial sequences drifts
    too far from zero (indicating bias).
    Returns the minimum p-value of forward and reverse modes.
    """
    bits = bytes_to_bits(data)
    n = len(bits)
    if n == 0:
        return 0.0

    # Convert to ±1
    X = np.array([1 if b == '1' else -1 for b in bits], dtype=np.float64)

    p_values = []
    for mode in range(2):  # 0 = forward, 1 = reverse
        seq = X if mode == 0 else X[::-1]
        S = np.cumsum(seq)
        z = float(np.max(np.abs(S)))

        if z == 0:
            p_values.append(1.0)
            continue

        # Compute p-value using the NIST formula
        sqrt_n = math.sqrt(n)
        sum_a = 0.0
        k_start = int((-n / z + 1) / 4)
        k_end = int((n / z - 1) / 4)
        for k in range(k_start, k_end + 1):
            term1 = _normal_cdf(((4 * k + 1) * z) / sqrt_n)
            term2 = _normal_cdf(((4 * k - 1) * z) / sqrt_n)
            sum_a += term1 - term2

        sum_b = 0.0
        k_start_b = int((-n / z - 3) / 4)
        k_end_b = int((n / z - 1) / 4)
        for k in range(k_start_b, k_end_b + 1):
            term1 = _normal_cdf(((4 * k + 3) * z) / sqrt_n)
            term2 = _normal_cdf(((4 * k + 1) * z) / sqrt_n)
            sum_b += term1 - term2

        p_val = 1.0 - sum_a + sum_b
        p_val = max(0.0, min(1.0, p_val))  # Clamp
        p_values.append(p_val)

    return min(p_values)


def _normal_cdf(x):
    """Standard normal CDF using erfc."""
    return 0.5 * math.erfc(-x / math.sqrt(2))


# ====================================================================
# Test 6: Approximate Entropy Test
# ====================================================================

def approximate_entropy_test(data, m=2):
    """
    Approximate Entropy Test — NIST SP 800-22.
    Compares the frequency of overlapping m-bit and (m+1)-bit patterns.
    Low entropy ⇒ predictable / repetitive structure.
    Returns the p-value.
    """
    if gammaincc is None:
        print("Warning: scipy is required for the Approximate Entropy Test.")
        return 0.0

    bits = bytes_to_bits(data)
    n = len(bits)
    if n < 64:
        return 0.0  # Need a minimum length for meaningful results

    phi = []
    for block_len in [m, m + 1]:
        # Augment the bit-string: append the first (block_len - 1) bits
        augmented = bits + bits[:block_len - 1]

        # Count occurrences of each pattern
        pattern_counts = {}
        for i in range(n):
            pattern = augmented[i:i + block_len]
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        # Compute phi_m
        total = sum(c ** 2 for c in pattern_counts.values())
        phi_m = math.log(total / (n ** 2)) if n > 0 else 0.0
        phi.append(phi_m)

    # ApEn = phi[0] - phi[1]
    ap_en = phi[0] - phi[1]

    chi_sq = 2 * n * (math.log(2) - ap_en)

    p_value = gammaincc(2 ** (m - 1), chi_sq / 2.0)
    return p_value


# ====================================================================
# Test 7: Serial Test
# ====================================================================

def serial_test(data, m=2):
    """
    Serial Test — NIST SP 800-22.
    Tests the uniformity of distribution of all possible m-bit overlapping
    patterns. Returns the minimum of p_value1 and p_value2.
    """
    if gammaincc is None:
        print("Warning: scipy is required for the Serial Test.")
        return 0.0

    bits = bytes_to_bits(data)
    n = len(bits)
    if n < 64:
        return 0.0

    def psi_sq(block_len):
        """Compute psi_squared for a given block length."""
        if block_len == 0:
            return 0.0
        augmented = bits + bits[:block_len - 1]
        pattern_counts = {}
        for i in range(n):
            pattern = augmented[i:i + block_len]
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        total_sq = sum(c ** 2 for c in pattern_counts.values())
        return (2 ** block_len / n) * total_sq - n

    psi_m = psi_sq(m)
    psi_m1 = psi_sq(m - 1)
    psi_m2 = psi_sq(m - 2) if m >= 2 else 0.0

    delta1 = psi_m - psi_m1
    delta2 = psi_m - 2 * psi_m1 + psi_m2

    p1 = gammaincc(2 ** (m - 2), delta1 / 2.0)
    p2 = gammaincc(2 ** (m - 3), delta2 / 2.0) if m >= 3 else gammaincc(0.5, delta2 / 2.0)

    return min(p1, p2)


# ====================================================================
# Test 8: Discrete Fourier Transform (Spectral) Test
# ====================================================================

def spectral_test(data):
    """
    DFT (Spectral) Test — NIST SP 800-22.
    Detects periodic features in the bit sequence by examining the
    peak heights in the Discrete Fourier Transform.
    Returns the p-value.
    """
    bits = bytes_to_bits(data)
    n = len(bits)
    if n < 64:
        return 0.0

    # Convert to ±1
    X = np.array([1.0 if b == '1' else -1.0 for b in bits])

    # DFT
    S = np.fft.fft(X)

    # Use only the first n/2 components (the rest are mirrors)
    half = n // 2
    M = np.abs(S[:half])

    # Threshold T = sqrt(log(1/0.05) * n)  (95% peak height threshold)
    T = math.sqrt(math.log(1 / 0.05) * n)

    # Count peaks below threshold
    N_0 = 0.95 * half  # Expected count under randomness
    N_1 = float(np.sum(M < T))  # Observed count

    d = (N_1 - N_0) / math.sqrt(n * 0.95 * 0.05 / 4)
    p_value = math.erfc(abs(d) / math.sqrt(2))

    return p_value


# ====================================================================
# Convenience: Run All Tests
# ====================================================================

def run_all_tests(data):
    """Convenience function to run all tests and return a dictionary of p-values."""
    return {
        "Monobit": monobit_test(data),
        "BlockFrequency": block_frequency_test(data, M=128),
        "Runs": runs_test(data),
        "LongestRun": longest_run_of_ones_test(data),
        "CumulativeSums": cumulative_sums_test(data),
        "ApproximateEntropy": approximate_entropy_test(data, m=2),
        "Serial": serial_test(data, m=2),
        "Spectral": spectral_test(data),
    }


# ====================================================================
# Standalone Execution
# ====================================================================

if __name__ == "__main__":
    import os
    print("Running NIST SP 800-22 tests on 10,000 random bytes...\n")
    test_data = os.urandom(10000)
    results = run_all_tests(test_data)

    print(f"{'Test':<25} {'P-Value':>10}  {'Pass (>=0.01)':>14}")
    print("-" * 55)
    for name, pval in results.items():
        status = "PASS ✓" if pval >= 0.01 else "FAIL ✗"
        print(f"{name:<25} {pval:>10.6f}  {status:>14}")
