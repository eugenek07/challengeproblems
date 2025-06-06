from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def sign(data, private_key):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def verify(signature, data, public_key):
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256))

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()
    return private_key, public_key
