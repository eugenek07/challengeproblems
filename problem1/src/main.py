# Assumption, both users have the public keys of their counterpart, and their own corresponding private keys.
import rsa
import hmac
import aes
import ecdsa

# Scheme
# Symmetric AES Key -> RSA() encryption -> Add Sha256 to create HMAC -> Sign with DSA
# Once we've shared symmetric AES key
# Plaintext -> AES() -> Ciphertext -> Sha256 HMAC -> Sign with DSA

# 

# 1st Task: Send over symmetric AES key
symmetric_aes_key = b'12345678123456781234567812345678'

    # Step 1: Encrypt symmetric AES key using RSA encryption
ciphertext = rsa.encrypt(symmetric_aes_key)

    # Step 2: Use SHA256 to create HMAC
cipher_hmac = hmac.addhmac(ciphertext, key)

