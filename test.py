from utils import decrypt_message, load_private_key

# Specify the sequence of routers used for encryption
router_sequence = [3, 2, 4, 1]  # Same sequence used during encryption

# Load Bob's private key
bob_private_key = load_private_key("bob_priv.pem")

# Load the encrypted message from alice_out.txt
with open("alice_out.txt", "r") as file:
    encrypted_message = file.read()

# Decrypt the message in the order of the router sequence
for router_number in router_sequence:
    router_private_key = load_private_key("r{}_priv.pem".format(router_number))
    encrypted_message = decrypt_message(encrypted_message, router_private_key)

# Decrypt the final message using Bob's private key
final_message = decrypt_message(encrypted_message, bob_private_key)

print("Decrypted message at Bob:", final_message)
