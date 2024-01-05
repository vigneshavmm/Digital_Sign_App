from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def sign_document(private_key_path, document):
    # Load private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    # Sign 
    signature = private_key.sign(
        document.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

private_key_path = "/Users/vigneshswaminathan/Downloads/project/private_key.pem"
document_to_sign = "This is the document to sign."

signature = sign_document(private_key_path, document_to_sign)
print("Signature:", signature.hex())