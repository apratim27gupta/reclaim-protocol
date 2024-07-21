from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json

# Generate ECDHE key pairs for client
def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Derive the shared secret using ECDHE
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Derive keys using HKDF
def derive_keys(shared_secret, salt, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        info=info,
    )
    key = hkdf.derive(shared_secret)
    return key

# Convert PEM string to private key object
def load_private_key(pem_str):
    private_key = serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None  # If your private key is encrypted, provide the password here
    )
    return private_key

# Getting key object from string
def load_public_key(pem_str):
    public_key = serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )
    return public_key


# Generating client
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
    key_dict = {"private" : client_private_pem,
                "public" : client_public_pem} 
    return key_dict

# Encrypting the message with the symmetric key
def encrypt_message(symmetric_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

# Decrypting the message with the symmetric key
def decrypt_message(symmetric_key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def generate_proof(encrypted_text, decrypted_text, key):
    """
    Stub Function to mock generating the partial exposed output and encrypted form along with all details needed for verification
    """
    return {}


# Attempt to get the partial decrypted and encrypted response (was unable to hence these functions remain ununused)
def process_packets(packets, reveal_field, original_dict):
    revealed_data = json.dumps({reveal_field: original_dict[reveal_field]}).encode('utf-8')
    print("This is revealed data : ", revealed_data)
    revealed_indices = set(range(len(revealed_data)))
    print("this is revelaed indices ", revealed_indices)
    processed_packets = []
    for packet in packets:
        if any(byte in revealed_data for byte in packet):
            processed_packet = bytearray(packet)
            for i in range(len(packet)):
                if i not in revealed_indices:
                    processed_packet[i] = ord('∗')
            processed_packets.append(bytes(processed_packet))
    
    return processed_packets
def divide_into_tls_packets(data, packet_size=16):
    return [data[i:i + packet_size] for i in range(0, len(data), packet_size)]

def process_response(enc_resp, key, reveal_field, decrypted_bytes, decrypted_str, decrypted_dict):
    revealed_data = {reveal_field: decrypted_dict[reveal_field]} if reveal_field in decrypted_dict else {}


    # Divide the response into TLS packets
    tls_packets = divide_into_tls_packets(decrypted_bytes)

    # Process the packets to retain only relevant data
    processed_packets = process_packets(tls_packets, reveal_field, decrypted_dict)
    # Combine processed packets into respp
    respp = b''.join(processed_packets)

    # Encrypt the modified response
    enc_respr = encrypt_message(key, respp)

    return {
        'enc_respr': enc_respr,
        'dec_enc_respr': revealed_data
    }
