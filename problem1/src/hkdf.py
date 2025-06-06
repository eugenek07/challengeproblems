import os
from cryptography.hazmat.primitves import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# How do we insert randomness into hkdf formula? 

def derive_keys(root):
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32,


    )
    hmac_key = HKDF()