import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# How do we insert randomness into hkdf formula?
# Key is sufficiently random
# Salt is random, doesn't need to be secret
# Application specific context information can be shared

# Reference: https://eprint.iacr.org/2010/264.pdf
# HKDF Scheme by Hugo Krawczyk
# Reference: https://datatracker.ietf.org/doc/html/rfc5869

# Public Salt Information
salt = b'1234123412341234'

def derive_keys(root):
    aes_generator = HKDF(
        algorithm = hashes.SHA256(), 
        length = 32,
        salt = salt,
        info = b"aes_key"
        )
    hmac_generator = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        info = b"hmac_key"
        )
    aes_key = aes_generator.derive(root)
    hmac_key = hmac_generator.derive(root)

    # Error Checking!
    # aes_generator.verify(root, aes_key)
    # hmac_key.verify(root, hmac_key)

    # Return Keys
    return aes_key, hmac_key

    
