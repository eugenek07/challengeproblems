# Assumption, both users have the public keys of their counterpart, and their own corresponding private keys.
# Assumption 2, both users share a secret key for HMAC purposes
import rsa
import hmac
import aes
import ecdsa

# Scheme
# Symmetric AES Key -> RSA() encryption -> Add Sha256 to create HMAC -> Sign with DSA
# Once we've shared symmetric AES key
# Plaintext -> AES() -> Ciphertext -> Sha256 HMAC -> Sign with DSA

#Goal: Confidentiality, Authenticity, Integrity

# 

# 1st Task: User 1 sends over symmetric AES key
symmetric_aes_key = b'12345678123456781234567812345678'

    # Step 1: Encrypt symmetric AES key using RSA encryption
ciphertext = rsa.encrypt(symmetric_aes_key, rsakey_public)

    # Step 2: Use SHA256 to create HMAC
cipher_hmac = hmac.addhmac(ciphertext, hmac_key)

    #Step 3: Sign cipher+hmac with DSA to verify authenticity
encrypted_message = ecdsa.sign(cipher_hmac, signaturekey_private)

# 2nd Task: User 2 receives encrypted message

    # Step 1: Verify Sign
cipher_hmac, verified = ecdsa.verify(encrypted_message, signaturekey_public)
if verified == False:
    print("ecdsa verification failed!")

    # Step 2: Decrypt Symmetric AES key using RSA decryption
plaintext = rsa.decrypt(cipher_hmac[0:32], rsakey_private)

    # Step 3: Use SHA256 to verify HMAC
verified = hmac.verifyhmac(plaintext, cipher_hmac[32:64], hmac_key)
if verified == False:
    print("hmac verification failed!")

#3rd Task: User 1 sends message
message = b'malazan rules!'

    #Step 1: Encrypt with AES key
ciphertext = aes.encrypt(message, symmetric_aes_key)

    #Step 2: Use SHA256 to create HMAC
cipher_hmac = hmac.addhmac(ciphertext, hmac_key)

    #Step 3: Sign cipher+hmac with DSA to verify authenticity
encrypted_message = ecdsa.sign(cipher_hmac, signaturekey_private)

#4th Task: User 2 decrypts message

    # Step 1: Verify Sign
cipher_hmac, verified = ecdsa.verify(encrypted_message, signaturekey_public)
if verified == False:
    print("ecdsa verification failed!")

    # Step 2: Decrypt Symmetric AES key using RSA decryption
plaintext = aes.decrypt(cipher_hmac[0:32], symmetric_aes_key)

    # Step 3: Use SHA256 to verify HMAC
verified = hmac.ssverifyhmac(plaintext, cipher_hmac[32:64], hmac_key)
if verified == False:
    print("hmac verification failed!")


if message == plaintext:
    print("Works!")
else:
    print("Doesn't Work!")