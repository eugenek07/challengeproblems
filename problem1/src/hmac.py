# References: 

from cryptography.hazmat.primitives import hashes, hmac

# generates HMAC for given ciphertext 
def add_hmac(ciphertext, hmac_key):
    enc_hmac = hmac.HMAC(hmac_key, hashes.SHA256())
    enc_hmac.update(ciphertext)
    mac = enc_hmac.finalize()
    return mac

# Verifies using cipher text if the mac matches the cipher text
def verify_hmac(ciphertext, mac, hmac_key):
    dec_hmac = hmac.HMAC(hmac_key, hashes.SHA256())
    dec_hmac.update(ciphertext)
    try:
        dec_hmac.verify(mac)
        return True
    except Exception as e:
        return False

    