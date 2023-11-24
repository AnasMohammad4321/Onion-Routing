from utils import encrypt_message, decrypt_message, generate_key_pair, load_private_key, get_next_router_public_key, load_public_key

ROUTER_NUMBER = 3

router_private_key = load_private_key("r3_priv.pem")

with open("router{}_in.txt".format(ROUTER_NUMBER), "r") as file:
    received_message = file.read()

decrypted_message = decrypt_message(received_message, router_private_key)

with open("router{}_out.txt".format(ROUTER_NUMBER), "w") as file:
    file.write(decrypted_message)
