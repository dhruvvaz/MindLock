import hashlib
import subprocess
from typing import Dict


def generate_key_from_pattern(user_input: Dict[str, object], template: str) -> bytes:
    """Evaluate the template using the provided user_input and derive
    a 256-bit AES key using SHA-256 on the result.

    Parameters
    ----------
    user_input: dict
        User supplied variables referenced in the template expression.
    template: str
        Expression involving keys of `user_input` returning a numeric or
        string result.

    Returns
    -------
    bytes
        32-byte key suitable for AES-256.
    """
    # Evaluate the expression in a restricted environment
    allowed_builtins = {
        'len': len,
        'int': int,
        'float': float,
        'str': str,
        'abs': abs,
        'max': max,
        'min': min,
    }
    value = eval(template, {'__builtins__': allowed_builtins}, dict(user_input))
    result_bytes = str(value).encode('utf-8')
    return hashlib.sha256(result_bytes).digest()


def _pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _derive_iv(key: bytes) -> bytes:
    return hashlib.sha256(key + b"iv").digest()[:16]


def encrypt(plaintext: str, key: bytes) -> bytes:
    iv = _derive_iv(key)
    padded = _pad_pkcs7(plaintext.encode('utf-8'))
    key_hex = key.hex()
    iv_hex = iv.hex()
    result = subprocess.run(
        [
            'openssl', 'enc', '-aes-256-cbc', '-K', key_hex, '-iv', iv_hex,
            '-nopad', '-nosalt', '-e'
        ],
        input=padded,
        capture_output=True,
        check=True
    )
    return result.stdout


def decrypt(ciphertext: bytes, key: bytes) -> str:
    iv = _derive_iv(key)
    key_hex = key.hex()
    iv_hex = iv.hex()
    result = subprocess.run(
        [
            'openssl', 'enc', '-aes-256-cbc', '-K', key_hex, '-iv', iv_hex,
            '-nopad', '-nosalt', '-d'
        ],
        input=ciphertext,
        capture_output=True,
        check=True
    )
    decrypted = _unpad_pkcs7(result.stdout)
    return decrypted.decode('utf-8')


def demo():
    user_inputs = {
        "birth_year": 2003,
        "locker_number": 136,
        "pet_name": "Luna",
    }
    template = "(birth_year % 97) + len(pet_name) + locker_number"
    key = generate_key_from_pattern(user_inputs, template)
    secret = "myFacebookPassword123"
    cipher = encrypt(secret, key)
    recovered = decrypt(cipher, key)
    print("Cipher (hex):", cipher.hex())
    print("Recovered:", recovered)


if __name__ == "__main__":
    demo()
