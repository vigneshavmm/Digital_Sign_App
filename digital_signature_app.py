from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

def sign_document(private_key_path, document):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    signature = private_key.sign(
        document.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {
        'document_content': document,
        'document_preview': document[:1000],  # Show the first 1000 characters as a preview
        'signature': signature.hex()
    }
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        private_key_path = "/Users/vigneshswaminathan/Downloads/project/private_key.pem"  # Replace with the actual path to your private key file
        uploaded_file = request.files['sample3']
        document_to_sign = uploaded_file.read().decode('utf-8')

        signed_document = sign_document(private_key_path, document_to_sign)
        return render_template('result_template.html', signed_document=signed_document)
    return render_template('index_template.html')

if __name__ == '__main__':
    app.run(debug=True)