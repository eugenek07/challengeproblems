from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes 

'''
    References: 
    1. https://gist.github.com/gabrielfalcao/de82a468e62e73805c59af620904c124
    2. https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
'''

def generate_keys():
    '''
        This function generates the public key pair, (n, e), and the private key pair, (n, d). The public key pair is used by the sender to encrypt the
        information and the private key is used by the receiver to decrypt the information
    '''
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048) 
    public_key = private_key.public_key() 
    return public_key, private_key


    # public_exponent is 'e' in the process of generating keys. Recall: choose e that is rel. prime to n
    # # because the public and private keys are objects, when we print them, they only show the object's location
    # # we can inspect the key by printing them in pem format like below
    # private_pem = PRIVATE_KEY.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # )

    # public_pem = PUBLIC_KEY.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )

    # print("Public Key in Pem Format: ", public_pem)
    # print("Private Key in Pem Format: ", private_pem)

def encrypt(plaintext, pub):
    '''
        This function encrypts the plaintext with the public key, pub. In terms of OAEP, the high-level idea is: 
            1. Pad the plaintext to be some 'k' bytes. Call the padded result, 'M'
            2. Create a random seed, 'r', of some size. 
            3. Use a Mask Generation Function (MGF), 'G', to make 'r' into 'k' bytes. Result is G(r) 
            4. The "fixed" plaintext is 'M' XOR 'G(r)'
    '''
    plaintext = plaintext.encode("utf-8")
    ciphertext = pub.encrypt(plaintext, padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()), 
                                                            algorithm = hashes.SHA256(), label = None)) 
                                                        
    
    return ciphertext

def decrypt(ciphertext, priv):
    '''
        This function decrypts the ciphertext with the private key, priv. 
    ''' 
    decrypted = priv.decrypt(ciphertext, padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
                                                      algorithm = hashes.SHA256(), label = None))
    decrypted = decrypted.decode("utf-8")
    return decrypted

# def main():
#     print("Let's start")
#     public_key, private_key = generate_keys()
#     plaintext = "Encrypt me" 
#     ciphertext = encrypt(plaintext, public_key)
#     decrypted = decrypt(ciphertext, private_key)

#     if plaintext == decrypted:
#         print("Encryption worked")
#     else: 
#         print(f"Your original plaintext was: {plaintext}. But your result was: {decrypted}")

# main()
