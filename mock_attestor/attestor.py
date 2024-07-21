from flask import Flask
from flask import Flask, request
from utils.key_generator import decrypt_message, add_signature
import requests

"""
Attestor Server. The purpose of this server is to act as a proxy for getting and sending requests. It does 2 tasks:
1. Verifies that indeed the API to hit is the API for the bank data
2. Adds a signature to the output so it can be verified that the data has indeed by verified
"""
app = Flask(__name__)
url_to_hit=''

@app.route('/proxy',  methods=['POST'])
def home():
    data = request.json

    global url_to_hit
    url_to_hit = decrypt_message(bytes.fromhex(data['key']), bytes.fromhex(data['url'])).decode('utf-8')

    return 'Successful'
    
@app.route('/send-request',  methods=['GET'])
def send_request():
    add_signature(requests.get(url_to_hit))
    return requests.get(url_to_hit).text
    
if __name__ == '__main__':
    app.run(debug=True, port=8001)
