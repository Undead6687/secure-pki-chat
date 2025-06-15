from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
import datetime
import base64
import os

# === Certificate & Key Loaders ===

def load_certificate(path):
    """Load a certificate from a PEM file."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_private_key(path):
    """Load a private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_root_ca_cert():
    """Load the Root CA certificate for verification."""
    return load_certificate("certificates/root_ca_cert.pem")


# === Signing & Verification ===

def sign_data(private_key, data):
    """Sign data with a private key."""
    if isinstance(data, str):
        data = data.encode('utf-8')

    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_data_signature(public_key, signature, data):
    """Verify a digital signature on data using a public key."""
    if isinstance(data, str):
        data = data.encode('utf-8')

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False



def generate_nonce(size=32):
    return base64.b64encode(os.urandom(size)).decode('utf-8')



# === Certificate Verification ===

def verify_certificate_chain(cert_to_verify, root_cert):
    try:
        # Verify the certificate's signature using the public key of the issuer (Root CA)
        root_public_key = root_cert.public_key()
        root_public_key.verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_verify.signature_hash_algorithm
        )

        # Verify that the issuer of the cert matches the subject of the root cert
        if cert_to_verify.issuer == root_cert.subject:
            print(f"[✓] Certificate '{cert_to_verify.subject.rfc4514_string()}' is verified by Root CA '{root_cert.subject.rfc4514_string()}'")
            return True
        else:
            print(f"[✗] Issuer mismatch: expected '{root_cert.subject.rfc4514_string()}', got '{cert_to_verify.issuer.rfc4514_string()}'")
            return False

    except Exception as e:
        print(f"[✗] Certificate chain verification failed: {e}")
        return False

def verify_certificate_signature_from_files(child_cert_path, issuer_cert_path):
    """Verify that a certificate file is signed by another certificate (like root_ca)."""
    child_cert = load_certificate(child_cert_path)
    issuer_cert = load_certificate(issuer_cert_path)
    issuer_public_key = issuer_cert.public_key()

    try:
        issuer_public_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm
        )
        print(f"{child_cert_path} is signed by {issuer_cert_path}")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


# === Encryption / Decryption ===

def encrypt_with_rsa(public_key, data):
    """Encrypt data using RSA-OAEP and a public key."""
    if isinstance(data, str):
        data = data.encode('utf-8')

    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_with_rsa(private_key, encrypted_data):
    """Decrypt data using RSA-OAEP and a private key."""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# === AES ===

def generate_aes_key():
    """Generate a random 256-bit AES key."""
    return os.urandom(32)  # 32 bytes = 256 bits