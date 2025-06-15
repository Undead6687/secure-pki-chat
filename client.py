import socket
import secrets
import threading
import json
import base64
import hashlib
import time
import struct
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from auth_utils import *
from encryption_utils import derive_key_from_components, encrypt_with_aes_gcm, decrypt_with_aes_gcm

# Global variables to store state
client_name = None
client_cert = None
client_key = None
root_ca_cert = None
client_certs = {}  # Store other clients' certificates
key_contributions = {}  # Store key contributions
group_key = None  # Final derived key
expected_clients = 3  # A, B, C
start_key_received = False  # Flag to indicate if start_key signal received

# --- Message framing utilities ---
def send_framed_message(sock, message_dict):
    """Send a message with proper framing."""
    message = json.dumps(message_dict).encode('utf-8')
    sock.sendall(struct.pack("!I", len(message)) + message)

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
    
    # Parse as JSON
    return json.loads(data.decode('utf-8'))

def receive_all(sock, n):
    """Receive exactly n bytes from the socket."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# --- Encryption/Decryption functions using cryptography library ---
def encrypt_message(message, key):
    """Encrypt a message using AES-GCM with HMAC."""
    # Generate a nonce
    nonce = os.urandom(12) 
    
    # Encode message
    message_bytes = message.encode('utf-8')
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Encrypt (tag is included in the ciphertext with AESGCM)
    ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
    
    # Create HMAC for additional integrity check
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message_bytes)
    hmac_digest = h.finalize().hex()
    
    # Return components as base64 strings
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "hmac": hmac_digest
    }

def decrypt_message(msg, key):
    """Decrypt a message encrypted with AES-GCM."""
    try:
        # Decode components from base64
        nonce = base64.b64decode(msg["nonce"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        
        # Create AESGCM object
        aesgcm = AESGCM(key)
        
        # Decrypt (this will verify the authentication tag)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Verify HMAC
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(plaintext)
        calculated_hmac = h.finalize().hex()
        
        if calculated_hmac != msg["hmac"]:
            return "[HMAC ERROR] Integrity check failed"
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"[DECRYPTION ERROR] {e}"

def verify_server_certificate(server_cert):
    """Verify that the server certificate was signed by the Root CA."""
    try:
        # Verify certificate chain
        if not verify_certificate_chain(server_cert, root_ca_cert):
            print("[✗] Server certificate validation failed")
            return False
        
        # Check the certificate's Common Name to ensure it's the server
        server_cn = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if server_cn != "server":
            print(f"[✗] Server certificate has unexpected Common Name: {server_cn}")
            return False
        
        return True
    
    except Exception as e:
        print(f"[✗] Server certificate verification error: {e}")
        return False

def broadcast_key_contribution(sock):
    """Broadcast encrypted key contribution to all clients."""
    global client_name, key_contributions, client_certs
    
    print("[*] Generating key contribution...")
    
    # Generate our key component (16 random bytes as hex string)
    my_random = os.urandom(16)
    my_contribution = my_random.hex()
    key_contributions[client_name] = my_contribution
    
    print(f"[✓] Generated contribution: {my_contribution[:10]}...")
    
    # Sign our contribution
    contribution_signature = sign_data(client_key, my_contribution)
    signature_b64 = base64.b64encode(contribution_signature).decode('utf-8')
    
    print(f"[✓] Signed contribution (signature length: {len(contribution_signature)} bytes)")
    
    # For each client, encrypt our contribution with their public key
    for recipient_name, recipient_cert in client_certs.items():
        if recipient_name == client_name:
            continue  # Skip ourselves
        
        print(f"[*] Encrypting contribution for {recipient_name}...")
        
        # Check if contribution is too large for RSA encryption
        recipient_public_key = recipient_cert.public_key()
        max_size = (recipient_public_key.key_size // 8) - 42  # RSA-OAEP overhead
        if len(my_contribution.encode()) > max_size:
            print(f"[!] Contribution too large for RSA encryption (max: {max_size} bytes)")
            continue
            
        # Encrypt our contribution with their public key
        encrypted_contribution = encrypt_with_rsa(recipient_public_key, my_contribution)
        encrypted_b64 = base64.b64encode(encrypted_contribution).decode('utf-8')
        
        print(f"[✓] Encrypted contribution for {recipient_name} (length: {len(encrypted_b64)} bytes)")
        
        # Send to specific recipient
        msg = {
            "type": "key_share",
            "sender": client_name,
            "recipient": recipient_name,
            "encrypted_contribution": encrypted_b64,
            "signature": signature_b64
        }
        
        send_framed_message(sock, msg)
        print(f"[✓] Sent encrypted key contribution to {recipient_name}")

def have_all_contributions():
    """Check if we have received contributions from all expected clients."""
    expected_clients_set = {'A', 'B', 'C'}
    return set(key_contributions.keys()) == expected_clients_set

def handle_incoming(sock):
    """Handle incoming messages in a separate thread."""
    global group_key, key_contributions, start_key_received
    
    while True:
        try:
            msg = receive_framed_message(sock)
            if not msg:
                print("[!] Connection to server lost.")
                break
            
            msg_type = msg.get('type')
            
            if msg_type == 'cert_distribution':
                # Store certificates of other clients
                print("[*] Received certificate distribution from server")
                for name, cert_data in msg['certificates'].items():
                    if name != client_name:
                        client_certs[name] = x509.load_pem_x509_certificate(
                            cert_data.encode('utf-8')
                        )
                        print(f"[✓] Received certificate for {name}")
            
            elif msg_type == 'start_key':
                # Server signals to start key exchange
                start_key_received = True
                print("[✓] Received start_key signal from server")
                # Broadcast our key contribution to all clients
                broadcast_key_contribution(sock)
            
            elif msg_type == 'key_share':
                # Process received key contribution
                sender = msg['sender']
                if sender == client_name:
                    continue  # Skip our own contribution
                
                recipient = msg.get('recipient')
                if recipient != client_name:
                    continue  # Skip messages meant for other clients
                
                print(f"[*] Received encrypted key contribution from {sender}")
                
                # Decrypt the contribution with our private key
                try:
                    encrypted_contribution = base64.b64decode(msg['encrypted_contribution'])
                    decrypted_contribution = decrypt_with_rsa(client_key, encrypted_contribution)
                    contribution = decrypted_contribution.decode('utf-8')
                    
                    print(f"[✓] Decrypted contribution from {sender}: {contribution[:10]}...")
                    
                    # Verify the signature
                    signature = base64.b64decode(msg['signature'])
                    sender_cert = client_certs[sender]
                    sender_public_key = sender_cert.public_key()
                    
                    if not verify_data_signature(sender_public_key, signature, contribution):
                        print(f"[!] Signature verification failed for contribution from {sender}")
                        continue  # Skip this contribution
                    
                    print(f"[✓] Verified signature from {sender}")
                    
                    # Store the verified contribution
                    key_contributions[sender] = contribution
                    
                    # Check if we have all contributions
                    if have_all_contributions():
                        print("[*] All key contributions received, deriving group key...")
                        derive_group_key()
                
                except Exception as e:
                    print(f"[!] Error processing contribution from {sender}: {e}")
            
            elif msg_type == 'group_chat':
                if group_key:
                    sender = msg.get('sender')
                    try:
                        text = decrypt_message(msg, group_key)
                        print(f"\n[{sender}]: {text}")
                    except Exception as e:
                        print(f"[!] Error decrypting message: {e}")
                else:
                    print("[!] Received message but group key not established yet")
            
        except socket.error as e:
            if hasattr(e, 'errno'):
                if e.errno == 10054:  # Connection reset by peer
                    print("[!] Server forcibly closed connection - exiting loop")
                    print("[!] Type 'exit' to exit the application")
                    break  # Exit the loop instead of continuing
                elif e.errno == 10053:  # Connection aborted
                    print("[!] Connection aborted - exiting loop")
                    print("[!] Type 'exit' to exit the application")
                    break
                else:
                    # Other socket errors - continue
                    print(f"[!] Socket error {e.errno}: {e} - continuing...")
                    continue
            else:
                print(f"[!] Socket error: {e} - exiting loop")
                print("[!] Type 'exit' to exit the application")
                break
        
        except Exception as e:
        # All other non-socket errors - continue processing
            print(f"[!] Error processing message: {e}") # Don't break on error, try to continue
            continue

def derive_group_key():
    """Derive the group key from all collected contributions using HKDF."""
    global key_contributions, group_key
    
    if group_key:
        return  # Already derived
    
    print("[*] Deriving group key with HKDF...")
    
    # Sort components by client name to ensure all clients derive the same key
    sorted_keys = [key_contributions[name] for name in sorted(key_contributions.keys())]
    print(f"[*] Using contributions from: {', '.join(sorted(key_contributions.keys()))}")
    
    # Use components as input to HKDF
    components = sorted_keys
    
    # Add session context (could be a timestamp or session ID)
    context = f"secure-chat-session-{int(time.time())}".encode()
    print(f"[*] Using context: {context.decode()}")
    
    # Derive the key
    group_key = derive_key_from_components(components, context=context)
    
    print(f"[✓] Group key established with HKDF: {group_key.hex()[:10]}...")

def authenticate_with_server(sock):
    """Authenticate with the server using certificates."""
    global client_name, client_cert, client_key
    
    print("[*] Authenticating with server...")
    
    # Send certificate to server
    auth_msg = {
        'type': 'authenticate',
        'name': client_name,
        'certificate': client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    }
    
    # Generate a nonce and sign it
    nonce = secrets.token_bytes(16)
    signature = sign_data(client_key, nonce)
    
    auth_msg['nonce'] = base64.b64encode(nonce).decode('utf-8')
    auth_msg['signature'] = base64.b64encode(signature).decode('utf-8')
    
    print(f"[*] Sending authentication with nonce (length: {len(nonce)} bytes) and signature")
    
    # Send authentication message
    send_framed_message(sock, auth_msg)
    
    # Receive response
    response_ = receive_framed_message(sock)
    if response_ and response_.get('status') == 'auth2':
        try:
            # Parse certificate
            server_cert_pem = response_.get('certificate')
            server_received_cert = x509.load_pem_x509_certificate(server_cert_pem.encode('utf-8'))
        
            # Verify certificate
            if not verify_server_certificate(server_received_cert):
                return False
            
            print(f"[✓] Certificate for Server validated with Root CA")
        
            # Get signature and nonce
            server_sent_signature = base64.b64decode(response_.get('signature'))
            server_nonce = response_.get('nonce')
        
            # Verify server identity and signature with the nonce we sent
            server_pub_key = server_received_cert.public_key()
        
            print(f"[*] Verifying signature from Server")
        
            # Verify the signature
            try:
                server_pub_key.verify(
                    server_sent_signature,
                    nonce,  # Our original nonce
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"[✓] Signature verified for Server")
            except Exception as e:
                print(f"[✗] Signature verification failed for Server: {e}")
                return False
        
            print(f"[✓] Sending Auth response to server...")
            # Send authentication success - sign the server's nonce
            client_signature = sign_data(client_key, server_nonce.encode('utf-8'))
            client_auth_response = {
                'status': 'authenticated',
                'signature': base64.b64encode(client_signature).decode('utf-8')
            }
            send_framed_message(sock, client_auth_response)
        
            # Wait for final authentication confirmation
            response = receive_framed_message(sock)
            if response and response.get('status') == 'authenticated':
                print("[✓] Successfully authenticated with server")
                return True
            else:
                reason = response.get('reason', 'unknown') if response else 'no response'
                print(f"[✗] Authentication failed: {reason}")
                return False
            
        except Exception as e:
            print(f"[✗] Authentication error: {e}")
            return False
    else:
        reason = "Server did not respond with auth2"
        print(f"[✗] Authentication failed: {reason}")
        return False

def chat_session(sock):
    """Main chat session after authentication."""
    global group_key, start_key_received
    
    # Start message receiving thread
    receiver_thread = threading.Thread(target=handle_incoming, args=(sock,), daemon=True)
    receiver_thread.start()
    
    # Wait for start_key signal
    print("[*] Waiting for start_key signal from server...")
    timeout = 30  # seconds
    start_time = time.time()
    while not start_key_received and time.time() - start_time < timeout:
        time.sleep(0.5)
    
    if not start_key_received:
        print("[!] Timed out waiting for start_key signal")
        return
    
    # Wait for group key to be established
    print("[*] Waiting for all key contributions and group key establishment...")
    timeout = 30  # seconds
    start_time = time.time()
    while not group_key and time.time() - start_time < timeout:
        time.sleep(0.5)
    
    if not group_key:
        print("[!] Timed out waiting for group key establishment")
        return
    
    # Chat message sending loop
    print("\n[*] Secure chat established. Type your messages:\n")
    while True:
        try:
            message = input("> ")
            if not message:
                continue
                
            if message.lower() == 'exit':
                break
            
            print(f"[*] Encrypting message with AES-GCM...")
            
            # Encrypt with group key
            encrypted = encrypt_message(message, group_key)
            
            # Send encrypted message
            chat_msg = {
                'type': 'group_chat',
                'sender': client_name,
                'nonce': encrypted['nonce'],
                'ciphertext': encrypted['ciphertext'],
                'hmac': encrypted['hmac']
            }
            
            send_framed_message(sock, chat_msg)
            print(f"[✓] Message sent")
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            # Don't break, allow retry

def start_client():
    """Start the client and connect to server."""
    global client_name, client_cert, client_key, root_ca_cert
    
    # Get client name
    client_name = input("Enter client name (A/B/C): ").strip().upper()
    if client_name not in ['A', 'B', 'C']:
        print("Invalid client name.")
        return
    
    # Load certificate and private key
    try:
        client_cert = load_certificate(f"certificates/{client_name}_cert.pem")
        client_key = load_private_key(f"certificates/{client_name}_key.pem")
        root_ca_cert = load_root_ca_cert()
        print(f"[✓] Loaded certificate and private key for {client_name}")
    except Exception as e:
        print(f"[✗] Failed to load certificates: {e}")
        return
    
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect(("127.0.0.1", 9999))
            print(f"[✓] Connected to server")
            
            # Authenticate
            if authenticate_with_server(sock):
                # Start chat session
                chat_session(sock)
        except Exception as e:
            print(f"[✗] Connection error: {e}")

if __name__ == "__main__":
    start_client()