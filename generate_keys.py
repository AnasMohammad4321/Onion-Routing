from Crypto.PublicKey import RSA

def generate_key_pair(entity_name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f'{entity_name}_priv.pem', 'wb') as f:
        f.write(private_key)
    with open(f'{entity_name}_pub.pem', 'wb') as f:
        f.write(public_key)

# Generate keys for Alice, Bob, R1, R2, R3, R4
generate_key_pair('alice')
generate_key_pair('bob')
generate_key_pair('r1')
generate_key_pair('r2')
generate_key_pair('r3')
generate_key_pair('r4')
