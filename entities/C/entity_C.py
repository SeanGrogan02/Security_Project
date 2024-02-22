import socket
import pickle
from cryptography.hazmat.primitives import serialization

# Load private key and public key certificate
with open('private_key_C.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open('public_key_cert_C.pem', 'rb') as f:
    public_key_cert = f.read()

# Socket communication setup
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Step 1: Authentication
    s.sendall(pickle.dumps(public_key_cert))
    # Signature of certificate
    signature = private_key.sign(public_key_cert)
    s.sendall(pickle.dumps(signature))

    # Step 2: Key Exchange
    session_key = b'Kabc'
    # Encrypt session key with public key of B
    # Send encrypted session key to Server S

    # Step 3: Secure Chat
    while True:
        # Send encrypted message signed with session key
        pass
