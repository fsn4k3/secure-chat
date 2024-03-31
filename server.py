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

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)

    print("Server listening on 127.0.0.1:12345...")

    client_socket, addr = server_socket.accept()
    print("Connection established with:", addr)

    # Server's private key
    private_key = RSA.import_key(open('keys/private_key.pem').read())
    
    # Server's public key
    public_key = RSA.import_key(open('keys/public_key.pem').read())

    # Receive and decode the encrypted shared secret from the client
    encrypted_shared_secret_client = client_socket.recv(4096)
    decoded_shared_secret_client = base64.b64decode(encrypted_shared_secret_client)

    # Decrypt the shared secret using the private key
    decrypted_shared_secret_client = decrypt_with_private_key(decoded_shared_secret_client, private_key)

    print("Decoded ciphertext:", decrypted_shared_secret_client.decode('utf-8'))

    # Continuous chat loop
    while True:
        message = input("Server: ")
        encrypted_message = encrypt_with_public_key(message.encode('utf-8'), private_key)
        client_socket.send(base64.b64encode(encrypted_message))

        # Receive and decrypt the client's message
        encrypted_message = client_socket.recv(4096)
        decrypted_message = decrypt_with_private_key(base64.b64decode(encrypted_message), private_key)
        print(f"Client: {decrypted_message.decode('utf-8')}")

    client_socket.close()

if __name__ == "__main__":
    start_server()
