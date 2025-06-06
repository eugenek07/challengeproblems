from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

def encrypt(plain_text, aes_key, iv):
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()
    return cipher_text

def decrypt(cipher_text, aes_key, iv):
    decrypter = Cipher.decryptor()
    plaintext = decrypter.update(cipher_text) + decrypter.finalize()
    return plaintext