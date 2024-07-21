# reclaim-protocol
Attempt at mocking the TLS protocol and WIP for a impl of Reclaim


This is a brief attempt (WIP) to setup a zero knowledge proof for an individual with any third party app about any specific information. 

The ZKP part is currently just a mock with an implementation to be added in the near future. 

There are 2 servers : mock server which represents any third party app, and attestor server which verifies the data and adds a signature. 

To set it up : 

1. Activate the virtual environment in pythonEnv
2. cd into mock server and execute the server.py file
3. cd into mock attestor and execute the attestor.py file
4. Run the py_client.py at home directory (this is the client which wants to claim and prove some info to another app)