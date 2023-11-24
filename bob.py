from utils import decrypt_message, load_private_key

# Load Bob's private key
bob_private_key = load_private_key("bob_priv.pem")
bob_public_key = load_private_key("bob_pub.pem")

# Load the received message from the last router
with open("bob_in.txt", "r") as file:
    received_message = file.read()

# Perform decryption using Bob's private key
decrypted_message = decrypt_message(received_message, bob_private_key)

print("Received message at Bob:", decrypted_message)
