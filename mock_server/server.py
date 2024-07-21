from flask import Flask
from flask import Flask, request, jsonify
import json
from utils.key_generator import get_ephemeral_keys, derive_shared_secret, derive_keys, encrypt_message
from utils.load_keys import load_private_key, load_public_key

"""
This is a resource server, emulating the final server, which contains the data that 
the user wants to have verified by the verifier. It could be a bank, Uber, Swiggy etc
"""
app = Flask(__name__)

server_keys = {}
final_session_keys = {}

# This API is used to create the ephemeral asymmetric keys and then returning the public key for TLS handshake
@app.route('/keys', methods=['GET'])
def get_ephemeral_endpoint():
    global server_keys
    server_keys = get_ephemeral_keys()
    response = {
        'public_key': server_keys['public'],
        'message': 'Data received successfully!'
    }

    return jsonify(response)


# This endpoint is used to receive the client's public API and then generate 
# the session keys for encryption and decryption
@app.route('/keys', methods=['POST'])
def post_keys():
    global server_keys
    global final_session_keys
    data = request.json
    shared_secret = derive_shared_secret(load_private_key(server_keys['private']), load_public_key(data['public']))
    salt = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    server_receiving_info = b'TLS handshake client-to-server sending'
    server_sending_info = b'TLS handshake client-to-server receiving'
    server_receiving_key = derive_keys(shared_secret, salt, server_receiving_info)
    server_sending_key = derive_keys(shared_secret, salt, server_sending_info)
    final_session_keys['receive'] = server_receiving_key
    final_session_keys['send'] = server_sending_key
    print("This is : ", final_session_keys)
    response = {
        # 'public_key': server_keys['public'],
        'message': 'Process Completed successfully!'
    }

    return jsonify(response)

# Mock User data which returns the user data. The data is returned by 
# encrypting the response data.
@app.route('/user-data', methods=['GET'])
def get_data():
    global final_session_keys
    user_data = {
        "name": "Apratim",
        "Balance": "120",
        "PAN": "ANCDE3421F",
        "Salary": "100"
    }
    print(encrypt_message(final_session_keys['send'], json.dumps(user_data).encode()))
    return encrypt_message(final_session_keys['send'], json.dumps(user_data).encode()).hex()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
