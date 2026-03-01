def encryption(text: str, key: int = 85) -> tuple[list[int], list[int]]:
    """Encrypts text using an LCG-based XOR cipher."""
    ascii_text = [ord(char) for char in text]
    a, c, m = 1664525, 1013904223, 256
    shared_key = []
    for _ in range(len(text)):
        key = (key * a + c) % m
        shared_key.append(key)
    encrypted_text = [
        char_val ^ key_val for char_val, key_val in zip(ascii_text, shared_key)
    ]
    return encrypted_text, shared_key


def decryption(encrypted_text: list[int], shared_key: list[int]) -> str:
    """Decrypts an encrypted list of integers using the shared key."""
    decrypted_ascii = [
        enc_val ^ key_val for enc_val, key_val in zip(encrypted_text, shared_key)
    ]
    return "".join(chr(val) for val in decrypted_ascii)
