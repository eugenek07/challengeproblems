# Assumption, both users have the public keys of their counterpart, and their own corresponding private keys.

# Symmetric AES Key -> RSA() encryption -> Add Sha256 to create HMAC -> Sign with DSA
# Once we've shared symmetric AES key
# Plaintext -> AES() -> Ciphertext -> Sha256 HMAC -> Sign with DSA

from cryptography.hazmat.primitives import hashes

 

def encrypt_mac(message, key):
