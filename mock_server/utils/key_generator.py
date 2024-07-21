from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_keys(shared_secret, salt, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Derive a single 32-byte key
        salt=salt,
        info=info,
    )
    key = hkdf.derive(shared_secret)
    return key

def load_private_key(pem_str):
    private_key = serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None  
    )
    return private_key

def load_public_key(pem_str):
    public_key = serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )
    return public_key


def get_ephemeral_keys():
    client_private_key, client_public_key = generate_ecdh_key_pair()
    client_private_pem = client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    client_public_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    # print(client_public_pem)
    key_dict = {"private" : client_private_pem,
                "public" : client_public_pem} 
    return key_dict

def encrypt_message(symmetric_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
