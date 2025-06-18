import hashlib
import json
import os
import ast
from typing import Dict, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ALLOWED_BUILTINS = {"len": len, "int": int, "float": float, "str": str}


def _safe_eval(expr: str, variables: Dict[str, object]):
    """Evaluate expression safely with restricted functions."""
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id not in variables and node.id not in ALLOWED_BUILTINS:
                raise ValueError(f"Unknown variable or function: {node.id}")
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_BUILTINS:
                func_name = getattr(node.func, 'id', 'unknown')
                raise ValueError(f"Function '{func_name}' not allowed")
    code = compile(tree, "<logic>", "eval")
    return eval(code, {"__builtins__": None, **ALLOWED_BUILTINS}, variables)


def generate_key_from_pattern(user_input: Dict[str, object], logic_template: str) -> bytes:
    """Generate a 256-bit key from a logic expression based on user input."""
    if not isinstance(user_input, dict):
        raise TypeError("user_input must be a dictionary")
    result = _safe_eval(logic_template, dict(user_input))
    return hashlib.sha256(str(result).encode()).digest()


def encrypt_message(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct


def decrypt_message(ciphertext: bytes, key: bytes) -> str:
    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode()


def save_vault_entry(label: str, encrypted_password: str, logic_template: str, vault_file: str = "vault.json") -> None:
    entry = {"label": label, "encrypted_password": encrypted_password, "logic_template": logic_template}
    try:
        with open(vault_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    data.append(entry)
    with open(vault_file, "w") as f:
        json.dump(data, f, indent=2)


def load_vault_entry(label: str, vault_file: str = "vault.json") -> Dict[str, str]:
    with open(vault_file, "r") as f:
        data = json.load(f)
    for entry in data:
        if entry.get("label") == label:
            return entry
    raise KeyError(f"Entry '{label}' not found")


def list_vault_entries(vault_file: str = "vault.json") -> List[str]:
    try:
        with open(vault_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    return [e.get("label", "") for e in data]


def cli():
    print("Enter variables (blank name to finish):")
    user_input = {}
    while True:
        name = input("Variable name: ").strip()
        if not name:
            break
        value = input(f"Value for '{name}': ")
        if value.isdigit():
            value = int(value)
        user_input[name] = value

    logic = input("Logic expression: ")
    try:
        key = generate_key_from_pattern(user_input, logic)
    except Exception as e:
        print(f"Error evaluating logic: {e}")
        return

    message = input("Message to encrypt: ")
    ciphertext = encrypt_message(message, key)
    print("Encrypted (hex):", ciphertext.hex())

    if input("Decrypt now? [y/N]: ").lower() == "y":
        try:
            recovered = decrypt_message(ciphertext, key)
            print("Decrypted:", recovered)
        except Exception as e:
            print("Decryption failed:", e)

    if input("Save to vault? [y/N]: ").lower() == "y":
        label = input("Label: ")
        save_vault_entry(label, ciphertext.hex(), logic)
        print("Saved.")


def demo():
    inputs = {"birth_year": 2003, "locker_number": 136, "pet_name": "Luna"}
    logic = "(birth_year % 97) + len(pet_name) + locker_number"
    key = generate_key_from_pattern(inputs, logic)
    plaintext = "myFacebookPassword123"
    ciphertext = encrypt_message(plaintext, key)
    recovered = decrypt_message(ciphertext, key)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted:", recovered)


if __name__ == "__main__":
    cli()
