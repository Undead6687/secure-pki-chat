# encryption_utils_enhanced.py
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import struct

# --- Message framing utilities ---
def send_framed_message(sock, data):
    """Send a message with proper framing to ensure complete transmission."""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    # Send length prefix followed by data
    sock.sendall(struct.pack("!I", len(data)) + data)

def receive_framed_message(sock):
    """Receive a message with proper framing."""
    # First 4 bytes are the length prefix
    raw_length = receive_all(sock, 4)
    if not raw_length:
        return None
    
    # Unpack the length
    length = struct.unpack("!I", raw_length)[0]
    
    # Now receive the actual message data
    data = receive_all(sock, length)
    if not data:
        return None
    
    # Try to parse as JSON, return raw bytes if it fails
    try:
        return json.loads(data.decode('utf-8'))
    except json.JSONDecodeError:
        return data

def receive_all(sock, n):
    """Receive exactly n bytes from the socket."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# --- Cryptographic utilities ---
def generate_aes_key(length=32):
    """Generate a random AES key of specified length (default: 32 bytes for AES-256)."""
    return os.urandom(length)

def encrypt_with_aes_gcm(key, plaintext):
    """Encrypt data with AES-GCM returning a dict with components."""
    # Convert string to bytes if needed
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate nonce
    nonce = os.urandom(12)
    
    # Create cipher and encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Return components as base64 strings in a dict
    return {
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_with_aes_gcm(key, encrypted_data):
    """Decrypt data that was encrypted with AES-GCM."""
    # Extract components
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # Create cipher and decrypt
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    # Try to decode as UTF-8, return bytes if it fails
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext

def derive_key_from_components(components, context=b""):
    """Derive a key using HKDF from multiple components."""
    # Concatenate all key components
    combined = b""
    for component in components:
        if isinstance(component, str):
            component = component.encode('utf-8')
        combined += component
    
    print(f"[*] HKDF input has {len(combined)} bytes")
    
    # Use HKDF to derive the final key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=None,
        info=context,
    )
    
    derived_key = hkdf.derive(combined)
    print(f"[✓] HKDF key derivation successful ({len(derived_key)} bytes)")
    return derived_key