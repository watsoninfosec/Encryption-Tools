from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair(public_key_path='public_key.pem', private_key_path='private_key.pem', key_size=4096):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Save the private key to a PEM file
    with open(private_key_path, 'wb') as private_key_file:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_bytes)
    
    # Extract the public key from the private key and save it to a PEM file
    public_key = private_key.public_key()
    with open(public_key_path, 'wb') as public_key_file:
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_bytes)

    print(f"RSA key pair generated successfully.\nPublic key saved to: {public_key_path}\nPrivate key saved to: {private_key_path}")

if __name__ == "__main__":
    generate_rsa_key_pair()
