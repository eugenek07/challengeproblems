from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def ecdsa_signature(data, private_key):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def ecdsa_verify(signature, data, public_key):
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256))

def ecdsa_generate_key():
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()
    return private_key, public_key
