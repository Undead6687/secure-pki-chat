from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

class RootCA:
    def __init__(self, ca_name="SecureChatRootCA"):
        self.ca_name = ca_name
        self.ca_cert_path = "certificates/root_ca_cert.pem"
        self.ca_key_path = "certificates/root_ca_key.pem"
        
        # Create certificates directory if it doesn't exist
        os.makedirs("certificates", exist_ok=True)
        
        # Check if CA cert and key already exist, if not generate them
        if not (os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path)):
            self._generate_ca_cert()
        
        # Load CA cert and key
        self._load_ca_cert_and_key()
    
    def _generate_ca_cert(self):
        """Generate a new Root CA certificate and private key"""
        print(f"[*] Generating new Root CA certificate for {self.ca_name}")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096  # Use 4096 bits for CA key
        )
        
        # Generate self-signed CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat System"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years validity
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(private_key, hashes.SHA256())
        
        # Save CA private key
        with open(self.ca_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save CA certificate
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[✓] Root CA certificate and key generated successfully")
    
    def _load_ca_cert_and_key(self):
        """Load the CA certificate and private key"""
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    def sign_csr(self, csr, entity_name, validity_days=365):
        """Sign a Certificate Signing Request"""
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).sign(self.ca_key, hashes.SHA256())
        
        return cert
    
    def generate_client_cert(self, entity_name, validity_days=365):
        """Generate a client key pair and certificate signed by the CA"""
        # Generate client key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create a CSR (Certificate Signing Request)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Chat System"),
            ])
        ).sign(private_key, hashes.SHA256())
        
        # Sign the CSR with our CA
        cert = self.sign_csr(csr, entity_name, validity_days)
        
        # Save private key
        key_path = f"certificates/{entity_name}_key.pem"
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save certificate
        cert_path = f"certificates/{entity_name}_cert.pem"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return cert, private_key

def main():
    # Create Root CA
    ca = RootCA()
    
    # Generate certificates for clients and server
    for entity in ["A", "B", "C", "server"]:
        print(f"[*] Generating certificate for {entity}")
        cert, _ = ca.generate_client_cert(entity)
        print(f"[✓] Certificate for {entity} generated successfully")
    
    print("[✓] All certificates generated. They can be found in the 'certificates' directory.")

if __name__ == "__main__":
    main()