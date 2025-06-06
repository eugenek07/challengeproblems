from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY = 0
PUBLIC_KEY = 0

def generate_keys():
    '''
        This function generates the public key pair, (n, e), and the private key pair, (n, d). The public key pair is used by the sender to encrypt the
        information and the private key is used by the receiver to decrypt the information
    '''
    PRIVATE_KEY = rsa.generate_private_key(public_exponent = 65537, key_size = 2048) # public_exponent is 'e' in the 
                                                                            # process of generating keys. 
                                                                        # Recall: choose e that is rel. prime to n
    PUBLIC_KEY = PRIVATE_KEY.public_key() 

    # because the public and private keys are objects, when we print them, they only show the object's location
    # we can inspect the key by printing them in pem format like below
    private_pem = PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Public Key in Pem Format: ", public_pem)
    print("Private Key in Pem Format: ", private_pem)

def encrypt(plaintext, priv):
    pass

def decrypt(ciphertext, pub):
    pass 

def main():
    print("Let's start")
    generate_keys()

main()
