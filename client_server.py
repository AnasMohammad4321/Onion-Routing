import sys
import socket
import json
import crypt
import base64
import struct
import logger
from random import shuffle
from cryptography.fernet import Fernet

DIRECTORY_PORT = 3001
CLIENT_PORT = 4050
DIRECTORY_IP = 'localhost'
HASH_DELIMITER = b'###'
AES_KEY = crypt.gen_aes_key()

def main(message):
    """
    Main function to perform onion routing and handle the communication with relay nodes.

    Args:
        message (str): The original user request (URL).

    Returns:
        None
    """
    logger.header('---- REQUEST RELAY NODES FROM DIRECTORY ----')
    relay_nodes = request_directory()
    logger.log('RELAY NODES: ', relay_nodes, True)
    logger.header('---- GENERATE CIRCUIT FOR ONION ROUTING ----')
    circuit = generate_circuit(relay_nodes)
    logger.log('CIRCUIT IS: ', circuit)
    circuit_copy = list(circuit)
    entry_node = circuit[0][0]
    logger.log('ENTRY NODE IS: ', entry_node, True)
    logger.header('---- BEGIN ENCRYPTION PROCESS TO WRAP ONION ----')
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    logger.header('---- END ENCRYPTION PROCESS TO WRAP ONION ----')
    logger.log('ENCRYPTED MESSAGE: ', encrypted_message, True)
    logger.header('---- SEND REQUEST TO ENTRY NODE ----')
    response = send_request(encrypted_message, entry_node)
    logger.log('...onion routing via relay nodes', 3, True)
    logger.log('...received response from destination')
    logger.log('...received response from destination')
    byteStream = decrypt_payload(response, circuit_copy)
    result = byteStream.decode()
    logger.header('---- DECODED RESPONSE FROM DESTINATION ----\n')
    logger.log('', result)
    # write result to html file
    logger.header('---- BEGIN WRITE RESULT TO HTML FILE ----')
    with open('response.html', 'w') as f:
        f.write(result)
    logger.header('---- END WRITE RESULT TO HTML FILE ----')
    logger.header('---- OPEN ./response.html TO SEE RESPONSE ----')

def request_directory():
    """
    Get a list of relay nodes from the directory.

    Returns:
        dict: Dictionary containing relay nodes information.
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(8192).decode()  # Payload is received as bytes, decode to get str type
    s.close()
    relay_nodes = json.loads(payload)
    return relay_nodes

def generate_circuit(nodes):
    """
    Randomly select the order of relay nodes.

    Args:
        nodes (dict): Dictionary containing relay nodes information.

    Returns:
        list: List of tuples representing relay nodes and their corresponding AES keys.
    """
    circuit = [(str(ip), crypt.gen_aes_key()) for ip in nodes.keys()]
    shuffle(circuit)
    return circuit

def serialize_payload(aes_key, message):
    """
    Encode payload for transmission.

    Args:
        aes_key (bytes): AES key.
        message (bytes): Message to be encoded.

    Returns:
        bytes: Encoded payload.
    """
    return base64.b64encode(aes_key + HASH_DELIMITER + message)

def encrypt_payload(message, circuit, relay_nodes):
    """
    Encrypt each layer of the request: rsa_encrypt(AES_key) + aes_encrypt(M + next).

    Args:
        message (str): The original user request (URL).
        circuit (list): List of tuples representing relay nodes and their corresponding AES keys.
        relay_nodes (dict): Dictionary containing relay nodes information.

    Returns:
        bytes: Encoded and encrypted payload.
    """
    node_stack = circuit
    next_node = message  # The final plaintext will be the original user request
    payload = b''
    while len(node_stack) != 0:
        curr_node = node_stack.pop()
        curr_node_addr = curr_node[0]
        curr_aes_key_instance = curr_node[1]
        public_key = base64.b64decode(relay_nodes[curr_node_addr][1])  # Decode public key here
        if isinstance(payload, tuple):
            encrypted_aes_key, encrypted_payload = payload
            payload = serialize_payload(encrypted_aes_key, encrypted_payload)
        # Encrypt payload
        payload = crypt.encrypt(curr_aes_key_instance, public_key, (payload + next_node.encode()))
        next_node = curr_node_addr

    return serialize_payload(payload[0], payload[1])

def decrypt_payload(payload, circuit):
    """
    Decrypt each layer of the request.

    Args:
        payload (bytes): Encoded and encrypted payload.
        circuit (list): List of tuples representing relay nodes and their corresponding AES keys.

    Returns:
        bytes: Decrypted message.
    """
    message = payload
    for i in range(len(circuit)):
        aes_key = circuit[i][1]

        if isinstance(message, tuple):
            encrypted_aes_key, encrypted_payload = message
            # Add padding to make the length a multiple of 4
            padding = b'=' * (4 - (len(encrypted_payload) % 4))
            encrypted_payload += padding
            decoded_message = base64.b64decode(encrypted_payload)
            print(f"Decoded message length: {len(decoded_message)}")
            message = crypt.decrypt_aes(aes_key, decoded_message)
        else:
            # Add padding to make the length a multiple of 4
            padding = b'=' * (4 - (len(message) % 4))
            message += padding
            decoded_message = base64.b64decode(message)
            print(f"Decoded message length: {len(decoded_message)}")
            message = crypt.decrypt_aes(aes_key, decoded_message)

    return message

def send_request(encrypted_message, entry_node):
    """
    Send a request to the first relay node.

    Args:
        encrypted_message (bytes): Encoded and encrypted payload.
        entry_node (str): Address of the entry relay node.

    Returns:
        bytes: Response from the destination.
    """
    host, port = entry_node.split(':')
    relay_socket = socket.socket()
    relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_socket.bind(('localhost', CLIENT_PORT))
    relay_socket.connect((host, int(port)))
    packet_size = struct.pack('>i', len(encrypted_message))
    payload = packet_size + encrypted_message
    relay_socket.sendall(payload)
    response = b""
    while True:
        incoming_buffer = relay_socket.recv(8192)
        print('buffer length', len(incoming_buffer), incoming_buffer)
        if not incoming_buffer:
            break
        response += incoming_buffer

    relay_socket.close()
    return response

if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise Exception('No URL entered')
    url = sys.argv[1]
    main(url)
