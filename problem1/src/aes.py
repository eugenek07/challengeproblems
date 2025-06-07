from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

# encrpyts using AES in CBC mode 
def encrypt(plain_text, aes_key):
    iv =  b'\x00' * 16 
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(plain_text) + encryptor.finalize()
    return cipher_text

# receiver decrypts using the senders ciphertext iv and shared key
def decrypt(cipher_text, aes_key):
    iv =  b'\x00' * 16 
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    plaintext = decrypter.update(cipher_text) + decrypter.finalize()
    return plaintext