import socket
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_with_private_key(encrypted_text, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_text = cipher.decrypt(encrypted_text)
    return decrypted_text

def encrypt_with_public_key(plain_text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_text = cipher.encrypt(plain_text)
    return encrypted_text

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    # Client's private key
    private_key = RSA.import_key(open('keys/private_key.pem').read())

    # Client's public key
    public_key = RSA.import_key(open('keys/public_key.pem').read())

    # Generate a shared secret and encrypt it with the server's public key
    shared_secret = "Shared secret from client to server"
    encrypted_shared_secret = encrypt_with_public_key(shared_secret.encode('utf-8'), public_key)

    # Send the encrypted shared secret to the server
    client_socket.send(base64.b64encode(encrypted_shared_secret))

    # Continuous chat loop
    while True:
        # Receive and decrypt the server's message
        encrypted_message = client_socket.recv(4096)
        decrypted_message = decrypt_with_private_key(base64.b64decode(encrypted_message), private_key)
        print(f"Server: {decrypted_message.decode('utf-8')}")

        message = input("Client: ")
        encrypted_message = encrypt_with_public_key(message.encode('utf-8'), public_key)
        client_socket.send(base64.b64encode(encrypted_message))

    client_socket.close()

if __name__ == "__main__":
    start_client()
