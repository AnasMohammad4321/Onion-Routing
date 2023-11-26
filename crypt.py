import os
import base64
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def gen_aes_key():
    """
    Generates an AES key using the Fernet recipe layer.

    Returns:
        bytes: A URL-safe base64-encoded 32-byte key.
    """
    key = Fernet.generate_key()
    return key

def encrypt_aes(key, plaintext_bytes):
    """
    Encrypts a message using AES.

    Args:
        key (bytes): AES Fernet key.
        plaintext_bytes (bytes): The message in bytes meant to be encrypted.

    Returns:
        bytes: Encrypted message.
    """
    token = Fernet(key).encrypt(plaintext_bytes)
    return token

def decrypt_aes(key, token):
    """
    Decrypts a message using AES.

    Args:
        key (bytes): AES Fernet key.
        token (bytes): The encrypted message.

    Returns:
        bytes: Decrypted message.
    """
    plaintext_bytes = Fernet(key).decrypt(token)
    return plaintext_bytes

def gen_rsa_keypair():
    """
    Generates an RSA key pair.

    Returns:
        tuple: Private key and public key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, message):
    """
    Encrypts a message using RSA.

    Args:
        public_key (object): RSA public key object.
        message (bytes): The message in bytes meant to be encrypted.

    Returns:
        bytes: Encrypted message.
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
             mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    """
    Decrypts a ciphertext using RSA private key.

    Args:
        private_key (bytes or object): Bytes or RSA private key object.
        ciphertext (bytes or str): Ciphertext to be decrypted.

    Returns:
        bytes: Decrypted message.
    """
    if not isinstance(ciphertext, bytes):
        raise Exception('Ciphertext should be of byte format, not ', type(ciphertext))

    if not isinstance(private_key, rsa.RSAPrivateKey):
        private_key = load_private_pem(private_key)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
             mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
        )
    )
    return plaintext

def get_pem_format(private_key, public_key):
    """
    Converts private and public keys to PEM format.

    Args:
        private_key (object): RSA private key object.
        public_key (object): RSA public key object.

    Returns:
        tuple: Private key and public key strings in PEM format.
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def load_private_pem(private_key_pem):
    """
    Converts private key in PEM format to a private key object.

    Args:
        private_key_pem (bytes): Bytes containing private key in PEM format.

    Returns:
        object: RSA private key object.
    """
    private_key = serialization.load_pem_private_key(
         private_key_pem,
         password=None,
         backend=default_backend()
    )
    return private_key

def encrypt(AES_key, public_key_pem, payload):
    """
    Encrypts a payload using AES and RSA.

    Args:
        AES_key (bytes): AES Fernet key.
        public_key_pem (bytes): RSA public key in PEM format.
        payload (bytes): The payload to be encrypted.

    Returns:
        tuple: Encrypted AES key and payload.
    """
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_payload = encrypt_aes(AES_key, payload)
    encrypted_aes_key = encrypt_rsa(public_key, AES_key)
    return encrypted_aes_key, encrypted_payload

def decrypt():
    """
    Placeholder for the decryption function.

    Returns:
        None
    """
    return

def decrypt_payload(AES_key, payload):
    """
    Decrypts a payload and extracts information.

    Args:
        AES_key (bytes): AES Fernet key.
        payload (bytes): The payload to be decrypted.

    Returns:
        tuple: Destination URL and relay node information.
    """
    decrypted_payload = (decrypt_aes(AES_key, payload)).decode('UTF8')
    ip_addr_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decrypted_payload)
    url_match = re.search(r'^((https?|ftp|smtp):\/\/)?(www.)?[a-z0-9]+\.[a-z]+(\/[a-zA-Z0-9#]+\/?)*$', decrypted_payload)
    localhost_match = re.search(r'localhost:\d{4}', decrypted_payload)
    destination = ''
    message = ''
    
    if url_match is not None:
        destination = url_match.group()
        message = ''
    elif localhost_match is not None:
        destination = localhost_match.group()
        message = decrypted_payload.replace(destination, '')
    elif ip_addr_match is not None:
        destination = ip_addr_match.group()
        message = decrypted_payload.replace(destination, '')
    else:
        raise Exception('No match was found')

    return destination, message
