import json
import requests
import os
from utils.key_generator import get_ephemeral_keys, derive_shared_secret, derive_keys, encrypt_message, decrypt_message, generate_proof, process_packets
from utils.load_keys import load_public_key, load_private_key

"""
This is a simulation of a client which wants to generate 
a ZKP. Maybe they want to prove their salary to someone else or 
bank account balance to someone. So this client would hit a mock API for bank account. 
Not including server certificate verification process
"""


def create_session_keys():
    """
    This simulates the TLS handshake, first generating ephemeral private and public keys, then using them to send 
    and receive public keys, and then generating session keys for encrypting and decrypting
    """

    # Generates asymmetric keys for the client
    key_dict = get_ephemeral_keys()

    # URL for the server for getting server public key
    url = 'http://127.0.0.1:5000/keys'

    # Fetching 
    response = requests.get(url)
    request_dic = {}
    request_dic['public'] = key_dict['public']

    # fetched server public key
    server_public_key = json.loads(response.text)
    
    # generating shared secret for client side
    shared_secret = derive_shared_secret(load_private_key(key_dict['private']), load_public_key(server_public_key['public_key']))
    
    # Post request for sending public key to server
    requests.post(url, json=request_dic)

    # salt for generating session keys
    salt = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    client_sending_info = b'TLS handshake client-to-server sending'
    client_receiving_info = b'TLS handshake client-to-server receiving'

    # Get Symmetric key for sending 
    client_sending_key = derive_keys(shared_secret, salt, client_sending_info)

    # Get Symmetric key for receiving
    client_receiving_key = derive_keys(shared_secret, salt, client_receiving_info)
    return client_sending_key, client_receiving_key


client_sending_key, client_receiving_key = create_session_keys()

# Simulating encrypting public part of the API request (Here the public part of the url to hit -> this is a mock bank API)
ciphertext = encrypt_message(client_sending_key, b"http://127.0.0.1:5000/user-data")

# URL for the attestor server
url = 'http://127.0.0.1:8001/proxy'

# The body also contains the sending key of the client. Ideally this should be encrypted in ideal case but this is just a mock implementation
body = {"url" : encrypt_message(client_sending_key, b"http://127.0.0.1:5000/user-data").hex(), "method": "GET", "key": client_sending_key.hex()}

# Sending request to attestor for the API 
requests.post(url, json=body)

# changes the session keys for both client and server, to simulate the key update process for private request data like cookies etc
client_sending_key, client_receiving_key = create_session_keys()

# API to send the request to attestor which will send the request to the server
url = 'http://127.0.0.1:8001/send-request'

# Fetching the encrypted response from the server via attestor. The attestor even if it wanted to
# cannot access the underlying data since it does not have access to the receiving key 
answer = requests.get(url)

# Decrypting the message. The message contains the text from server and also the digital signature (mock) from the attestor
decrypted_bytes = decrypt_message(client_receiving_key, bytes.fromhex(answer.text))
decrypted_str = decrypted_bytes.decode('utf-8')

decrypted_dict = json.loads(decrypted_str)
print("This is the returned dictionary from server : ", decrypted_dict)

# Mock function to generate the final proof. The proof should expose the partial derypted data, along with the initial
# encrypted response and final encypted data. The verifier should ensure the correct string was decrypted and the decryption
# was performed correctly by running the ZK Verify function
zkProof = generate_proof(bytes.fromhex(answer.text), decrypted_dict, client_receiving_key)




# value = process_response(bytes.fromhex(answer.text), client_receiving_key, 'Salary', decrypted_bytes, decrypted_str, decrypted_dict)
# # print(decrypt_message(client_receiving_key, answer.text.encode()).decode('utf-8'))


