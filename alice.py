from utils import encrypt_message, load_private_key, load_public_key

# Load Alice's private key
bob_public_key = load_public_key("bob_pub.pem")

# Message to be sent
message = "Hello, Bob!"

# Specify the sequence of routers
router_sequence = [3, 2, 4, 1]  # Adjust this sequence as needed

# Encrypt the message in reverse order of the router sequence
for router_number in reversed(router_sequence):
    router_public_key = load_public_key("r{}_pub.pem".format(router_number))
    message = encrypt_message(message, router_public_key)

# Save the final encrypted message
with open("alice_out.txt", "w") as file:
    file.write(message)
