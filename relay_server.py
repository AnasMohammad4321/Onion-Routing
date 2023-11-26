import socket
import json
import base64
import requests
import traceback
import crypt
import network
import logger

DIRECTORY_PORT = 3001
RELAY_PORT = 5001
FORWARDING_PORT = 7001
HASH_DELIMITER = b'###'
DECRYPTED_AES_KEY = ''
PRIVATE_KEY = ''

def main():
    """
    Main function to set up the relay node and handle incoming requests.
    """
    # get RSA private key
    global PRIVATE_KEY
    PRIVATE_KEY = get_private_key()
    # open socket connection
    listen()    

def listen():
    """
    Listen for incoming connections on the relay node's designated port and handle incoming requests.
    """
    try:
        serversocket = network.start_server('localhost', RELAY_PORT)
        next_ip = None
        while True:
            logger.log('CURRENT RELAY NODE: ' + str(RELAY_PORT))
            logger.log('RECIEVING PORT:' + str(RELAY_PORT) + ' FORWARDING PORT:' + str(FORWARDING_PORT))

            clientsocket, address = serversocket.accept()
            payload = network.recv_by_size(clientsocket)
            previous_ip = parse_address(address)
            logger.log('received payload from: ', previous_ip)
            logger.log('Payload (trunc): ', payload[:100], newline=True)
            logger.header('---- BEGIN DECRYPTION OF RECEIVED PAYLOAD ----')
            next_ip, message = deserialize_payload(payload)

            logger.log('begin forwarding payload to next node...')
            response = forward_payload(next_ip, message)
            if response is not None:
                '''
                Case: send to previous_ip
                '''
                # encrypt layer
                logger.log('Response returned from: ' + next_ip, newline=True)
                logger.header('---- BEGIN ENCRYPTION OF RETURN PAYLOAD ----')
                logger.log('Payload being encrypted (trunc):', response[:100])

                logger.log('aes_key used:', DECRYPTED_AES_KEY)
                encrypted_payload = network.prepend_length(serialize_payload(response))

                logger.log('send payload to previous node: ', previous_ip)
                clientsocket.sendall(encrypted_payload)

            clientsocket.close()
    except Exception:
        logger.error("Unable to connect to server")
        logger.error(traceback.format_exc()) 
    return

def deserialize_payload(payload):
    """
    Deserialize the received payload and extract the next relay node's IP and the decrypted message.

    Args:
        payload (bytes): The received payload.

    Returns:
        tuple: A tuple containing the next relay node's IP and the decrypted message.
    """
    decoded_payload = base64.b64decode(payload)
    logger.log('Decoded Payload (rsa_encrypt(aes_key) + aes_encrypt(payload)):', decoded_payload, newline=True)
    encrypted_aes_key, encrypted_message = split_bytes(HASH_DELIMITER, decoded_payload)
    global DECRYPTED_AES_KEY
    DECRYPTED_AES_KEY = crypt.decrypt_rsa(PRIVATE_KEY, encrypted_aes_key)
    next_ip, message = crypt.decrypt_payload(DECRYPTED_AES_KEY, encrypted_message) # decrypted_message = encypted_payload + next_ip
    logger.log('Decrypted AES Key:', DECRYPTED_AES_KEY)
    logger.log('Decrypted Payload:', next_ip, message)
    logger.header('---- END DECRYPTION OF RECEIVED PAYLOAD ----', newline=True)
    return next_ip, message

def serialize_payload(message):
    """
    Serialize the message by encrypting it with the decrypted AES key.

    Args:
        message (bytes): The message to be serialized.

    Returns:
        bytes: The serialized payload.
    """
    if not isinstance(message, bytes):
        raise Exception('Message should be of byte format, not ', type(message))

    aes_encrypted_message = crypt.encrypt_aes(DECRYPTED_AES_KEY, message)
    return base64.b64encode(aes_encrypted_message)

def forward_payload(next_ip, message):
    """
    Forward the payload to the next relay node or the destination.

    Args:
        next_ip (str): The IP address of the next relay node or the destination.
        message (bytes): The message to be forwarded.

    Returns:
        bytes: The response from the next node or destination.
    """
    if is_exit_node(message):
        logger.log('EXIT NODE FOUND')
        logger.log('begin request to destination')
        req = requests.get(next_ip)
        return req.text.encode()

    else:
        logger.log('RELAY NODE FOUND')
        logger.log('next relay node is: ' + next_ip)
        message = message.encode()
        host, port = next_ip.split(':')
        relay_socket = network.connect_server('localhost', FORWARDING_PORT, host, port)
        payload = network.prepend_length(message)
        relay_socket.sendall(payload)
        response = network.recv_by_size(relay_socket)

        relay_socket.close()
        return response

    return

def is_exit_node(message):
    """
    Check if the relay node is an exit node.

    Args:
        message (bytes): The message to be checked.

    Returns:
        bool: True if the relay node is an exit node, False otherwise.
    """
    return True if message == '' else False

def parse_address(addr):
    """
    Parse the address tuple (IP, port) into a formatted string.

    Args:
        addr (tuple): The address tuple.

    Returns:
        str: The formatted address string.
    """
    return addr[0] + ':' + str(addr[1])

def split_bytes(delimiter, bytestring):
    """
    Split a bytestring into two parts using a delimiter.

    Args:
        delimiter (bytes): The delimiter to use for splitting.
        bytestring (bytes): The bytestring to be split.

    Returns:
        tuple: A tuple containing the two parts of the split bytestring.
    """
    if not isinstance(delimiter, bytes):
        raise Exception('Delimiter used should be of byte format, not ', type(delimiter))
    hash_index = bytestring.find(delimiter)
    encrypted_aes_key = bytestring[:hash_index]
    encrypted_message = bytestring[hash_index + len(delimiter):]

    return encrypted_aes_key, encrypted_message

def get_private_key():
    """
    Retrieve the RSA private key from the directory.

    Returns:
        bytes: The RSA private key.
    """
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', DIRECTORY_PORT))
    payload = directory_socket.recv(8192) # payload is received as bytes, decode to get as string
    directory_socket.close()
    relay_nodes = json.loads(payload)
    private_key = base64.b64decode(relay_nodes['localhost:' + str(RELAY_PORT)][0])

    return private_key

if __name__ == '__main__':
    main()
