import socket
import struct
import random

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import base64

def get_derived_key(client):
    # Receive server_public_key_bytes from the server
    server_public_key_bytes = client.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Generate a private key for use in the key exchange.
    parameters = server_public_key.parameters()
    client_private_key = parameters.generate_private_key()

    # Serialize the public key to send it to the server
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Send client_public_key_bytes to the server
    client.send(client_public_key_bytes)

    # Derive the shared secret
    shared_key = client_private_key.exchange(server_public_key)

    # Derive a symmetric key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    encoded_derived_key = base64.b64encode(derived_key)

    return encoded_derived_key

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 12345))

    # Get the derived key
    derived_key = get_derived_key(client)

    # Create a Fernet object with the derived key
    cipher_suite = Fernet(derived_key)

    global_event_counter = 0
    client_event_counter = 0

    while True:
        # Message to send
        msg = input("Enter a message to send (or 'quit!' to quit): ")

        if msg.lower() == 'quit!':
            break

        # Encrypt the message
        encrypted_msg = cipher_suite.encrypt(msg.encode('utf-8'))

        # Pack the headers
        headers = struct.pack('>BHIHH', 0, len(encrypted_msg) + 11, random.randint(0, 65535), global_event_counter, client_event_counter)

        # Send the message
        client.send(headers + encrypted_msg)

        # Receive the response
        response = client.recv(1024)

        # Unpack the headers
        msg_type, msg_len, msg_id, global_event_counter, client_event_counter = struct.unpack('>BHIHH', response[:11])

        # Get the encrypted message
        encrypted_msg = response[11:]

        # Check if the encrypted message is correctly formatted
        if len(encrypted_msg) % 4 != 0:
            print("Error: Incorrectly formatted encrypted message")
            continue

        # Decrypt the message
        try:
            msg = cipher_suite.decrypt(encrypted_msg).decode('utf-8')
        except InvalidToken:
            print("Error: Unable to decrypt message. The message may have been tampered with or the wrong key was used.")
            continue

        # Decrypt the message
        # msg = cipher_suite.decrypt(encrypted_msg).decode('utf-8')

        print(f"Received response: {msg}")

    client.close()


if __name__ == '__main__':
    start_client()