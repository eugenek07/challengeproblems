from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
import os

# encrpyts using AES in CBC mode 
def encrypt(plain_text, aes_key, iv):
    padder = padding.PKCS7(128).padder()
    padded_pt = padder.update(plain_text) + padder.finalize()
    
    encrypter = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    return encrypter.update(padded_pt) + encrypter.finalize()

# receiver decrypts using the senders ciphertext iv and shared key
def decrypt(cipher_text, aes_key, iv):
    decrypter = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded_plain_text = decrypter.update(cipher_text) + decrypter.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()