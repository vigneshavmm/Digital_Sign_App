from flask import Flask, render_template, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def serialize_public_key(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

def serialize_private_key(private_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_bytes

def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def is_valid(public_key_bytes, signature, message):
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Verification failed:", e)
        return False

private_key, public_key = generate_key_pair()
public_key_bytes = serialize_public_key(public_key)
private_key_bytes = serialize_private_key(private_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign():
    global private_key

    message = request.form['message']
    signature = sign_message(private_key, message.encode('utf-8'))

    return render_template('index.html', message=message, result="Signature: {}".format(signature.hex()))

@app.route('/verify', methods=['POST'])
def verify():
    global public_key_bytes

    message = request.form['message']
    signature = bytes.fromhex(request.form['signature'])
    
    is_signature_valid = is_valid(public_key_bytes, signature, message.encode('utf-8'))

    return render_template('index.html', message=message, result="Verification: {}".format("Valid" if is_signature_valid else "Invalid"))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    global public_key

    message = request.form['message']
    ciphertext = encrypt_message(public_key, message.encode('utf-8'))

    return render_template('index.html', message=message, result="Ciphertext: {}".format(ciphertext.hex()))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    global private_key

    ciphertext = bytes.fromhex(request.form['ciphertext'])
    plaintext = decrypt_message(private_key, ciphertext)

    return render_template('index.html', result="Decrypted Message: {}".format(plaintext.decode('utf-8')))

if __name__ == '__main__':
    app.run(debug=True, port=5001)