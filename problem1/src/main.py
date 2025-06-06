# Assumption, both users have the public RSA/ECDSA keys of their counterpart, and their own corresponding private keys.
# Assumption 2, both users share a secret key for HMAC purposes
import rsa
import hmac
import aes
import ecdsa
import hkdf
import os

# Scheme
# Initial Handshake: Message(Root Key) -> RSA() encryption -> Sign with ECDSA()
# From root key -> KDF() -> AES shared key, HMAC shared key
# File: Message(Plaintext) -> AES() -> Ciphertext -> Sha256 HMAC


#Goal: Confidentiality, Authenticity, Integrity

# 1st Task: Sender sends over root key (randomly generated)
rootkey = os.random(32) # Need to check size necessary for root key

    # Step 1: Encrypt rootkey using RSA encryption
ciphertext = rsa.encrypt(rootkey, rsakey_public)

    #Step 3: Sign ciphertext with ECDSA to verify authenticity
encrypted_message = ecdsa.sign(ciphertext, signaturekey_private)

# 2nd Task: Receiver receives encrypted message

    # Step 1: Verify Sign
ciphertext, verified = ecdsa.verify(encrypted_message, signaturekey_public)
if verified == False:
    print("ecdsa verification failed!")

    # Step 2: Decrypt Symmetric AES key using RSA decryption
plaintext = rsa.decrypt(ciphertext, rsakey_private)

# 3rd Task: Sender and Receiver both generate shared AES key and HMAC key from root

    # Step 1:
sender_aes_key, sender_hmac_key = hkdf.derive_keys(rootkey)
receiver_aes_key, receiver_hmac_key = hkdf.derive_keys(rootkey)

#4th Task: User 1 sends message
message = b'malazan rules!'

    #Step 1: Encrypt with AES key
ciphertext = aes.encrypt(message, sender_aes_key)

    #Step 2: Use SHA256 to create HMAC
cipher_hmac = hmac.addhmac(ciphertext, sender_hmac_key)

#4th Task: User 2 decrypts message

    # Step 1: Decrypt Symmetric AES key using RSA decryption
plaintext = aes.decrypt(cipher_hmac[0:32], receiver_aes_key)

    # Step 2: Use SHA256 to verify HMAC
verified = hmac.verifyhmac(plaintext, cipher_hmac[32:64], receiver_hmac_key)
if verified == False:
    print("hmac verification failed!")

if message == plaintext:
    print("Works!")
else:
    print("Doesn't Work!")