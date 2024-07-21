from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

# Convert PEM string to private key object
def load_private_key(pem_str):
    private_key = serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None  # If your private key is encrypted, provide the password here
    )
    return private_key

# Convert PEM string to public key object
def load_public_key(pem_str):
    public_key = serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )
    return public_key
