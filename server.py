import asyncio
import signal
import struct
from multiprocessing import Value

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import base64

# Generate a private key for use in the key exchange.
parameters = dh.generate_parameters(generator=2, key_size=2048)
server_private_key = parameters.generate_private_key()

# Serialize the public key to send it to the client
server_public_key_bytes = server_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create a shared memory integer for the global counter
global_counter = Value('i', 0)

def validate_message(cipher_suite, msg_data, msg_len):
    # Validate the message length
    if len(msg_data) != msg_len - 11:
        return 'Error: Incorrect message length'
    
    # Decrypt the message
    try:
        msg_data = cipher_suite.decrypt(msg_data)
    except InvalidToken:
        return 'Error: Invalid message'

    # Validate the message encoding
    try:
        msg = msg_data.decode('utf-8')
    except UnicodeDecodeError:
        return 'Error: Message not properly UTF-8 encoded'

    # Validate the message length
    if len(msg) > 500:
        return 'Error: Message too long'

    return msg

def validate_headers(headers_data):
    print(f"Received headers: {headers_data}")
    # Unpack the headers
    try:
        msg_type, msg_len, _msg_id, _global_event_counter, _client_event_counter = struct.unpack('>BHIHH', headers_data)
    except struct.error:
        return 'Error: Incorrect headers format'
    except ValueError:
        return 'Error: Incorrect headers format'

    if len(headers_data) != 11:
        return 'Error: Incorrect headers length'

    # Validate the message type
    if msg_type != 0:
        return 'Error: Incorrect message type'

    # Validate the message length
    if msg_len < 11:
        return 'Error: Incorrect message length in headers'

    return None

async def handle_client(reader, writer):
    # Send server_public_key_bytes to the client
    writer.write(server_public_key_bytes)
    await writer.drain()

    # Receive client_public_key_bytes from the client
    client_public_key_bytes = await reader.read(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

    # Derive the shared secret
    shared_key = server_private_key.exchange(client_public_key)

    # Derive a symmetric key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    encoded_derived_key = base64.b64encode(derived_key)

    cipher_suite = Fernet(encoded_derived_key)

    client_counter = 0

    while True:
        # Receive the headers
        headers_data = await reader.read(11)
        if not headers_data:
            break

        # Validate and Unpack the headers
        error_msg = validate_headers(headers_data)
        if error_msg:
            print(error_msg)
            error_msg = cipher_suite.encrypt(error_msg.encode('utf-8'))
            error_headers = struct.pack('>BHIHH', 1, len(error_msg) + 11, 0, global_counter.value, client_counter)
            writer.write(error_headers + error_msg)
            await writer.drain()
            break

        _, msg_len, msg_id, _, _ = struct.unpack('>BHIHH', headers_data)

        # Receive the encrypted message
        encrypted_msg_data = await reader.read(msg_len - 11)
        
        # Decrypt and Validate the message
        msg = validate_message(cipher_suite, encrypted_msg_data, msg_len)
        if 'Error' in msg:
            print(msg)
            error_msg = cipher_suite.encrypt(msg.encode('utf-8'))
            error_headers = struct.pack('>BHIHH', 1, len(error_msg) + 11, msg_id, global_counter.value, client_counter)
            writer.write(error_headers + error_msg)
            await writer.drain()
            break

        # Swap the case of the message
        msg = msg.swapcase()

        # Encrypt the message
        encrypted_msg = cipher_suite.encrypt(msg.encode('utf-8'))

        # Update the counters
        with global_counter.get_lock():
            global_counter.value += 1
            print('Global counter:', global_counter.value)
        client_counter += 1
        print('Client counter:', client_counter)

        # Pack the headers
        headers = struct.pack('>BHIHH', 1, len(encrypted_msg) + 11, msg_id, global_counter.value, client_counter)

        print(f"Received message: {encrypted_msg}")

        # Send a response
        writer.write(headers + encrypted_msg)
        await writer.drain()

    writer.close()

async def start_server(ready_event=None):
    server = await asyncio.start_server(handle_client, 'localhost', 12345)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    print('Server is ready')


    # Handle the interrupt signal
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, stop_server, server, loop)

    try:
        async with server:
            await server.serve_forever()

            if ready_event != None:
                ready_event.set()
    except asyncio.CancelledError:
        print('Server has been cancelled.')
    finally:
        # Ensure the server is closed
        server.close()
        await server.wait_closed()
        print('Server has been closed.')

def stop_server(server, loop):
    print('Stopping server...')

    # Initiate the shutdown
    server.close()

if __name__ == '__main__':
    asyncio.run(start_server())