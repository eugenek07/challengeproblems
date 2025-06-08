from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
import os

# encrpyts using AES in CBC mode 
def encrypt(plain_text, aes_key): # plain_text must be in bytes, not a string that's decoded! 
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_pt = padder.update(plain_text) + padder.finalize()
    
    encrypter = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    return iv + encrypter.update(padded_pt) + encrypter.finalize()

# receiver decrypts using the senders ciphertext iv and shared key
def decrypt(cipher_text_with_iv, aes_key):
    iv = cipher_text_with_iv[:16]
    cipher_text = cipher_text_with_iv[16:]
    decrypter = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded_plain_text = decrypter.update(cipher_text) + decrypter.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()