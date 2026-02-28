#!/usr/bin/env python3
"""Iperius Backup credential decryptor.

Encryption: AES-256-CBC via TurboPower LockBox 3 StreamToBlock
KDF:        SHA-1(password_UTF16LE), extended to 32 bytes by repeating first 12
IV:         first 8 bytes of ciphertext + 8 zero bytes
Format:     [8-byte seed] + [AES-256-CBC encrypted UTF-16LE plaintext]
"""
import hashlib, base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_PASSWORD = 'Errore: cartella gi\u00e0 esistente. Ricrearla ?'

def derive_key(password: str) -> bytes:
    sha1 = hashlib.sha1(password.encode('utf-16-le')).digest()  # 20 bytes
    return sha1 + sha1[:12]                                      # 32 bytes

def decrypt(ciphertext_b64: str, password: str = DEFAULT_PASSWORD) -> str:
    ct  = base64.b64decode(ciphertext_b64)
    key = derive_key(password)
    iv  = ct[:8] + b'\x00' * 8          # seed + 8 zero bytes
    enc = ct[8:]

    if len(enc) % 16 == 0 and len(enc) > 0:
        plaintext = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(enc)
    else:
        plaintext, chain = b'', iv
        for i in range(len(enc) // 16):
            blk = enc[i*16:(i+1)*16]
            dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(blk)
            plaintext += bytes(a ^ b for a, b in zip(dec, chain))
            chain = blk
        rem = enc[len(enc)//16*16:]
        if rem:
            ks = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(chain)
            plaintext += bytes(a ^ b for a, b in zip(rem, ks))

    return plaintext.decode('utf-16-le')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <base64_ciphertext> [password]")
        sys.exit(1)
    pwd = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PASSWORD
    print(f"Decrypted: {decrypt(sys.argv[1], pwd)}")
