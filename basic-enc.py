from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key_from_file(filename):
    with open(filename, "rb") as key_file:
        key = key_file.read()
    return key

def encrypt_with_public_key(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private_key(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Example usage:

# Alice generates her key pair
alice_private_key, alice_public_key = generate_key_pair()

# Save Alice's public key to a file (this would be shared with Bob)
save_key_to_file(alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), "alice_public_key.pem")

# Bob loads Alice's public key from the file
alice_public_key_loaded = serialization.load_pem_public_key(
    load_key_from_file("alice_public_key.pem"),
    backend=default_backend()
)

# Bob generates his key pair
bob_private_key, bob_public_key = generate_key_pair()

# Save Bob's public key to a file (this would be shared with Alice)
save_key_to_file(bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), "bob_public_key.pem")

# Alice loads Bob's public key from the file
bob_public_key_loaded = serialization.load_pem_public_key(
    load_key_from_file("bob_public_key.pem"),
    backend=default_backend()
)

# Alice encrypts a message with Bob's public key
plaintext_message = b"Hello, Bob! Let's exchange a secret key."
ciphertext = encrypt_with_public_key(bob_public_key_loaded, plaintext_message)

# Bob decrypts the message with his private key
decrypted_message = decrypt_with_private_key(bob_private_key, ciphertext)

print("Original Message:", plaintext_message.decode('utf-8'))
print("Encrypted Message:", ciphertext)
print("Decrypted Message:", decrypted_message.decode('utf-8'))
