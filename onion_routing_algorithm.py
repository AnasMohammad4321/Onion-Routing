from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

class OnionRouter:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def encrypt(self, message, next_router):
        recipient_key = RSA.import_key(next_router.public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        enc_session_key = cipher_rsa.encrypt(session_key)
        return base64.b64encode(enc_session_key + cipher_aes.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        data = base64.b64decode(ciphertext)
        enc_session_key = data[:256]
        nonce = data[256:272]
        tag = data[272:288]
        ciphertext = data[288:]

        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_message.decode()

def make_onion(message, route):
    onion = message
    sender = route[0]
    for i in reversed(route[1:]):
        onion = sender.encrypt(onion, i)
    return onion

def unwrap_1layer_onion(current_router, recieved_message):
    return current_router.decrypt(recieved_message)

def unwrap_all_layers(onion, route):
    dec = onion
    for i in route[1:]:
        dec = unwrap_1layer_onion(i,dec)
        print(f"Message recieved at Router {i.name}:",dec)
    return dec

if __name__ == "__main__":
    message = "Hi im fatima"
    router = OnionRouter("1")
    router2 = OnionRouter("2")
    router3 = OnionRouter("3")
    router4 = OnionRouter("4")
    route = [router, router2, router3, router4]

    onion = make_onion(message, route)
    print("Onion for route [1->2->3->4]:",onion)

    actual_message = unwrap_all_layers(onion, route)