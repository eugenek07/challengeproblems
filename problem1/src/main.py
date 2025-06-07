# Assumption, both users have the public RSA/ECDSA keys of their counterpart, and their own corresponding private keys.
# Assumption 2, both users share a secret key for HMAC purposes
import os
import rsa, my_hmac, aes, ecdsa, hkdf

# Scheme
# Initial Handshake: Message(Root Key) -> RSA() encryption -> Sign with ECDSA()
# From root key -> KDF() -> AES shared key, HMAC shared key
# File: Message(Plaintext) -> AES() -> Ciphertext -> Sha256 HMAC

#  TEST: Large File Sending
# Step 1: encrypt the large file 16 bytes at a time into an intermediate text file 
# Step 2: decrypt the intermediate text file 16 bytes at a time into a final file 
# Step 3: if the original file (large_test.txt) content matches the final file, the encryption/decryption is correct

# creating a large file of 10MB...
with open("large_test.txt", "wb") as f:
    f.write(os.urandom(10000000))


#Goal: Confidentiality, Authenticity, Integrity

# 1st Task: Sender sends root key (randomly generated)
rootkey = os.urandom(32) # Need to check size necessary for root key
iv = os.urandom(16)
rsakey_public, rsakey_private = rsa.generate_keys()
signaturekey_public, signaturekey_private = ecdsa.generate_keys()

    # Step 1: Encrypt rootkey using RSA encryption
ciphertext = rsa.encrypt(rootkey, rsakey_public)

    #Step 2: Sign ciphertext with ECDSA to verify authenticity
signature = ecdsa.sign(ciphertext, signaturekey_private)

# 2nd Task: Receiver receives ciphertext and signature 

    # Step 1: Verify the signature
verified = ecdsa.verify(signature, ciphertext, signaturekey_public)
if verified == False:
    print("ecdsa verification failed!")

    # Step 2: Decrypt the ciphertext to get the rootkey
plaintext = rsa.decrypt(ciphertext, rsakey_private)

# 3rd Task: Sender and Receiver both generate shared AES key and HMAC key from root

    # Step 1: generate the shared AES and HMAC keys
sender_aes_key, sender_hmac_key = hkdf.derive_keys(rootkey)
receiver_aes_key, receiver_hmac_key = hkdf.derive_keys(plaintext) # now, our symmetric tunnel is created. Ready to start 
                                                                    # encrypting...

# #4th Task: User 1 sends message
# message = b'malazan rules!'

#     #Step 1: Encrypt with AES key
# ciphertext = aes.encrypt(message, sender_aes_key, iv)

#     #Step 2: Use SHA256 to create HMAC
# cipher_hmac = my_hmac.add_hmac(ciphertext, sender_hmac_key)

# #4th Task: User 2 decrypts message

#     # Step 1: Use SHA256 to verify HMAC
# verified = my_hmac.verify_hmac(ciphertext, cipher_hmac, receiver_hmac_key)

#     # Step 2: Decrypt Symmetric AES key using RSA decryption
# plaintext = aes.decrypt(ciphertext, receiver_aes_key, iv)

# if verified == False:
#     print("hmac verification failed!")

# if message == plaintext:
#     print("Works!")
# else:
#     print("Doesn't Work!")

# 4th Task: send a large file, 16 bytes at a time, to the sender. We will check each chunk to see if it is 
# properly sent. If any chunk is not properly sent, then we will stop checking more. This simulates a user
# receiving each chunk, verifying it, and writing it to their resulting file ONLY IF everything worked fine

with open("large_test.txt", 'rb') as fp: 
    byte_chunk = fp.read(16) # read 16 bytes. Note: type(chunk) = byte! 
    while byte_chunk: 
        ciphertext = aes.encrypt(byte_chunk, sender_aes_key, iv) # encrypting the chunk
        ciper_hmac = my_hmac.add_hmac(ciphertext, sender_hmac_key) # hashing the chunk
        verified = my_hmac.verify_hmac(ciphertext, ciper_hmac, receiver_hmac_key) # verify the integrity of the chunk
        if not verified: 
            print("Something was tampered with in this chunk! Aborting...")
            exit()
        plaintext = aes.decrypt(ciphertext, receiver_aes_key, iv) # decrypt the chunk
        if plaintext != byte_chunk: 
            print("The original chunk is not the same as the decrypted chunk! Aborting...")
            exit()
        byte_chunk = fp.read(16)

# if we leave the loop, then we know we are done and everything is correct
print("Everything was done correctly!")
