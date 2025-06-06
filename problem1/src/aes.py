from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

def encrypt(message, aes_key):
    iv = os.urandmon(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext

def decrypt(message, aes_key, iv)