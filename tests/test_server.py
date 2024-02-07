import pytest
import asyncio
import struct
from ..server import start_server
import threading

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import base64

@pytest.fixture(scope="module", autouse=True)
async def server():
    # Create an event to signal when the server is ready
    ready_event = asyncio.Event()

    def start_server_sync():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_server(ready_event))

    # Start the server in a separate thread
    server_thread = threading.Thread(target=start_server_sync)
    server_thread.start()

    # Wait for the server to be ready
    await ready_event.wait()

    yield

    # Stop the server
    server_thread.join()

async def generate_key(reader, writer):
    # Receive server_public_key_bytes from the server
    server_public_key_bytes = await reader.read(1024)
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
    writer.write(client_public_key_bytes)
    await writer.drain()

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

@pytest.mark.asyncio
async def test_valid_message():
    await asyncio.sleep(10)

    # Connect to the server
    reader, writer = await asyncio.open_connection('127.0.0.1', 12345)

    # Generate the key
    encoded_derived_key = await generate_key(reader, writer)
    cipher_suite = Fernet(encoded_derived_key)

    # Message to send
    msg = "Test message"

    # Encrypt the message
    encrypted_msg = cipher_suite.encrypt(msg.encode('utf-8'))

    # Pack the headers
    headers = struct.pack('>BHIHH', 0, len(encrypted_msg) + 11, 12345, 0, 0)

    # Send the encrypted message
    writer.write(headers + encrypted_msg)
    await writer.drain()

    # Receive the response
    response = await reader.read(1024)

    # Unpack the headers
    msg_type, msg_len, msg_id, global_event_counter, client_event_counter = struct.unpack('>BHIHH', response[:11])

    # Get the encrypted message
    encrypted_received_msg = response[11:]

    # Decrypt the message
    received_msg = cipher_suite.decrypt(encrypted_received_msg).decode('utf-8')

    # Check the response
    assert msg_type == 1
    assert msg_len == len(encrypted_received_msg) + 11
    assert msg_id == 12345
    assert client_event_counter == 1
    assert received_msg == msg.swapcase()

    # Close the connection
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
async def test_invalid_message_length():
    # Connect to the server
    reader, writer = await asyncio.open_connection('localhost', 12345)

    # Generate the key
    encoded_derived_key = await generate_key(reader, writer)
    cipher_suite = Fernet(encoded_derived_key)

    # Message to send
    msg = "Test message"

    # Encrypt the message
    encrypted_msg = cipher_suite.encrypt(msg.encode('utf-8'))

    # Incorrectly pack the headers with a length that doesn't match the message
    headers = struct.pack('>BHIHH', 0, len(encrypted_msg) + 20, 12345, 0, 0)

    # Send the message
    writer.write(headers + encrypted_msg)
    await writer.drain()

    # Receive the response
    response = await reader.read(1024)

    # Get the encrypted message
    encrypted_received_msg = response[11:]

    # Decrypt the message
    received_msg = cipher_suite.decrypt(encrypted_received_msg).decode('utf-8')

    # Close the connection
    writer.close()
    await writer.wait_closed()

    # Check that the server responded with an error
    assert 'Error: Incorrect message length' in received_msg

@pytest.mark.asyncio
async def test_bad_data():
    # Connect to the server
    reader, writer = await asyncio.open_connection('localhost', 12345)

    # Generate the key
    encoded_derived_key = await generate_key(reader, writer)
    cipher_suite = Fernet(encoded_derived_key)

    # Message to send
    msg = b'Bad data'

    # Encrypt the message
    encrypted_msg = cipher_suite.encrypt(msg)

    # Send bad data
    writer.write(encrypted_msg)
    await writer.drain()

    # Receive the response
    response = await reader.read(1024)

    # Get the encrypted message
    encrypted_received_msg = response[11:]

    # Decrypt the message
    received_msg = cipher_suite.decrypt(encrypted_received_msg).decode('utf-8')

    # Close the connection
    writer.close()
    await writer.wait_closed()

    # Check that the server responded with an error
    assert 'Error: Incorrect message type' in received_msg

@pytest.mark.asyncio
async def test_non_utf8_message():
    # Connect to the server
    reader, writer = await asyncio.open_connection('localhost', 12345)

    # Generate the key
    encoded_derived_key = await generate_key(reader, writer)
    cipher_suite = Fernet(encoded_derived_key)

    # Message to send
    msg = b'\x80abc'

    # Encrypt the message
    encrypted_msg = cipher_suite.encrypt(msg)

    # Pack the headers
    headers = struct.pack('>BHIHH', 0, len(encrypted_msg) + 11, 12345, 0, 0)

    # Send the message
    writer.write(headers + encrypted_msg)
    await writer.drain()

    # Receive the response
    response = await reader.read(1024)

    # Get the encrypted message
    encrypted_received_msg = response[11:]

    # Decrypt the message
    received_msg = cipher_suite.decrypt(encrypted_received_msg).decode('utf-8')

    # Close the connection
    writer.close()
    await writer.wait_closed()

    # Check that the server responded with an error
    assert 'Error: Message not properly UTF-8 encoded' in received_msg
