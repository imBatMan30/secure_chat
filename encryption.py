import os
import base64
import hashlib
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def is_valid_gmail(email):
    """Validate that the email is a Gmail address"""
    pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return bool(re.match(pattern, email))

def generate_rsa_key_pair():
    """Generate a new RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_private_key(private_key_pem, password):
    """Encrypt the private key with a password"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    return encrypted_pem.decode('utf-8')

def decrypt_private_key(encrypted_private_key_pem, password):
    """Decrypt the private key with a password"""
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_pem.encode('utf-8'),
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        print(f"Error decrypting private key: {e}")
        return None

def load_public_key(public_key_pem):
    """Load a public key from PEM format"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def generate_aes_key():
    """Generate a random AES key"""
    return os.urandom(32)

def encrypt_with_rsa(public_key, data):
    """Encrypt data with RSA public key"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_with_rsa(private_key, encrypted_data):
    """Decrypt data with RSA private key"""
    if isinstance(encrypted_data, str):
        encrypted_data = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def encrypt_with_aes(key, data):
    """Encrypt data with AES key"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return {
        'encrypted': base64.b64encode(encrypted_data).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

def decrypt_with_aes(key, encrypted_data, iv):
    """Decrypt data with AES key"""
    if isinstance(encrypted_data, str):
        encrypted_data = base64.b64decode(encrypted_data)
    if isinstance(iv, str):
        iv = base64.b64decode(iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.rstrip(b'\0')

def hash_password(password):
    """Hash a password or security answer with salt"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    """Verify a password or security answer against its hash"""
    salt, key = stored_password.split(':')
    salt = bytes.fromhex(salt)
    key = bytes.fromhex(key)
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return key == new_key