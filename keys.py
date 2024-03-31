from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_self_signed_certificate(private_key, public_key, subject_name, issuer_name, days_valid=365):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(
        private_key, hashes.SHA256()
    )

    return cert

def save_key_to_file(key, filename, private=True):
    if private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(filename, 'wb') as key_file:
        key_file.write(pem)


def save_cert_to_file(cert, filename):
    with open(filename, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    # Server
    server_private_key, server_public_key = generate_key_pair()
    server_certificate = generate_self_signed_certificate(
        server_private_key, server_public_key, "Server", "Server"
    )

    save_key_to_file(server_private_key, "private_key.pem", private=True)

    save_cert_to_file(server_certificate, "server_certificate.pem")
    save_key_to_file(server_public_key, "server_public_key.pem", private=False)


    # Client
    client_private_key, client_public_key = generate_key_pair()
    client_certificate = generate_self_signed_certificate(
        client_private_key, client_public_key, "Client", "Client"
    )

    save_key_to_file(client_private_key, "client_private_key.pem", private=True)

    save_cert_to_file(client_certificate, "client_certificate.pem")
    save_key_to_file(client_public_key, "client_public_key.pem", private=False)

    
    # Load an existing private key from file

    with open("private_key.pem", "rb") as key_file:
	    private_key = serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	    )
    
    # Extract the corresponding public key
    public_key = private_key.public_key()

    # Save the public key to a file
    with open("public_key.pem", "wb") as key_file:
	    key_file.write(public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	    ))

    

