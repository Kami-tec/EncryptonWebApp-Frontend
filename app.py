from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import logging

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Encryption methods
def quantum_encryption(plaintext):
    """
    Simulated Quantum Encryption (Base64 encoding for simplicity).
    """
    encrypted_message = base64.b64encode(plaintext.encode()).decode()
    return encrypted_message

def hybrid_encryption(plaintext):
    """
    Simulated Hybrid Encryption: Combines symmetric encryption (AES) and key encryption.
    """
    symmetric_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    encrypted_message = base64.b64encode(iv + encrypted_key + ciphertext).decode()
    return encrypted_message

def asymmetric_encryption(plaintext):
    """
    RSA-based Asymmetric Encryption.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    encrypted_message = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_message).decode()

# Routes
@app.route('/')
def home():
    """
    Serve the main HTML page.
    """
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt a message using the specified encryption method.
    """
    data = request.json
    message = data.get('message')
    method = data.get('method')

    if not message or not method:
        return jsonify({'error': 'Message and encryption method are required'}), 400

    try:
        if method == 'quantum':
            encrypted_message = quantum_encryption(message)
        elif method == 'hybrid':
            encrypted_message = hybrid_encryption(message)
        elif method == 'asymmetric':
            encrypted_message = asymmetric_encryption(message)
        else:
            return jsonify({'error': 'Invalid encryption method'}), 400

        return jsonify({'encryptedMessage': encrypted_message})
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Decryption functionality is not implemented.
    """
    return jsonify({'error': 'Decryption is not implemented'}), 501

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    logger.error(f"404 Error: {e}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Error: {e}")
    return render_template('500.html'), 500

# API Example
@app.route('/api/data')
def get_data():
    """
    Example API route for data processing.
    """
    try:
        data = {"message": "Success"}
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

# Run the app
if __name__ == '__main__':
    app.run(debug=True)