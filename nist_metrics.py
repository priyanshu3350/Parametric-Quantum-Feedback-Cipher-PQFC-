import math
try:
    from scipy.special import gammaincc
except ImportError:
    gammaincc = None

def bytes_to_bits(data):
    """Converts a bytes-like object to a string of '0' and '1's."""
    if isinstance(data, str):
        # Assume it's already a binary string if it only contains 0 and 1
        if set(data).issubset({'0', '1'}):
            return data
    return "".join(format(byte, '08b') for byte in data)

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

def run_all_tests(data):
    """Convenience function to run all tests and return a dictionary of p-values."""
    return {
        "Monobit": monobit_test(data),
        "BlockFrequency": block_frequency_test(data, M=128),
        "Runs": runs_test(data)
    }
