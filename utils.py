import base64

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    aes_key = base64.b64encode(private_key)[:16]
    return aes_key, public_key


def load_private_key(filename):
    with open(filename, "r") as file:
        private_key = file.read()
    return private_key

def load_public_key(filename):
    with open(filename, "r") as file:
        public_key = file.read()
    return public_key

def xor_encrypt(message, key):
    encrypted_message = bytearray()
    for i in range(len(message)):
        encrypted_message.append(message[i] ^ key[i % len(key)])
    return bytes(encrypted_message)

def xor_decrypt(ciphertext, key):
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

def encrypt_message(message, public_key):
    key = base64.b64encode(public_key.encode())
    encrypted_message = xor_encrypt(message.encode(), key)
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(ciphertext, private_key):
    key = base64.b64encode(private_key.encode())
    decrypted_message = xor_decrypt(base64.b64decode(ciphertext), key)
    return decrypted_message.decode()

def get_next_router_public_key(router_number):
    filename = "r{}_pub.pem".format(router_number + 1)
    return load_public_key(filename) if router_number < 4 else None
