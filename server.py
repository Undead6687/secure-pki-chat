import socket
import threading
import json
import base64
import struct
import hashlib
from auth_utils import *
from cryptography.x509.oid import NameOID

# Global state
server_cert = None
server_key = None
root_ca_cert = None
client_connections = {}  # name -> socket
client_certs = {}        # name -> certificate
expected_clients = 3     # A, B, C
lock = threading.Lock()  # Thread safety

# --- Message framing utilities ---
def send_framed_message(sock, message_dict):
    """Send a message with proper framing to ensure complete transmission."""
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
    
    # Try to parse as JSON
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

def handle_client(conn, addr):
    """Handle individual client connections."""
    client_name = None
    
    try:
        print(f"[+] New connection from {addr}")
        
        # Receive and process authentication
        auth_msg = receive_framed_message(conn)
        if not auth_msg or auth_msg.get('type') != 'authenticate':
            print(f"[✗] Invalid authentication message from {addr}")
            send_framed_message(conn, {'status': 'authentication_failed', 'reason': 'invalid_message'})
            return
        
        client_name = auth_msg.get('name')
        cert_pem = auth_msg.get('certificate')
        
        print(f"[*] Processing authentication from {client_name}")
        
        try:
            # Load client certificate
            client_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            
            # Verify certificate chain
            if not verify_certificate_chain(client_cert, root_ca_cert):
                print(f"[✗] Certificate validation failed for {client_name}")
                send_framed_message(conn, {'status': 'authentication_failed', 'reason': 'invalid_certificate'})
                return
            
            print(f"[✓] Certificate for {client_name} validated with Root CA")
            
            # Verify client identity and signature
            client_public_key = client_cert.public_key()
            nonce = base64.b64decode(auth_msg.get('nonce'))
            signature = base64.b64decode(auth_msg.get('signature'))
            
            print(f"[*] Verifying signature from {client_name}")
            
            # Verify the signature
            try:
                client_public_key.verify(
                    signature,
                    nonce,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"[✓] Signature verified for {client_name}")
            except Exception as e:
                print(f"[✗] Signature verification failed for {client_name}: {e}")
                send_framed_message(conn, {'status': 'authentication_failed', 'reason': 'invalid_signature'})
                return
            
            # Store client information
            with lock:
                client_certs[client_name] = client_cert
                client_connections[client_name] = conn
                print(f"[*] Client information stored: {client_name}")
            
            # Send server authentication success
            server_signature = sign_data(server_key, nonce)
            server_nonce = generate_nonce()
            server_auth_response = {
                'status': 'auth2',
                'certificate': server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                'nonce':  server_nonce,
                'signature': base64.b64encode(server_signature).decode('utf-8'),
                }
            send_framed_message(conn, server_auth_response)
            client_auth_response = receive_framed_message(conn)
            if not client_auth_response or client_auth_response.get('status') != 'authenticated':
                print(f"[✗] Invalid authentication response from {client_name}")
                send_framed_message(conn, {'status': 'authentication_failed', 'reason': 'invalid_response'})
                return
            cert_pem = client_auth_response.get('certificate')
            print(f"[*] Processing authentication from {client_name}")
            try:
                client_signature = base64.b64decode(client_auth_response.get('signature', ''))
                client_public_key = client_cert.public_key()
                client_public_key.verify(
                    client_signature,
                    server_nonce.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"[✓] Client {client_name} verified server nonce")
                send_framed_message(conn, {'status': 'authenticated'})
                print(f"[✓] Client {client_name} authenticated successfully")
            except Exception as e:
                print(f"[!] Error processing client {addr}: {e}")
                send_framed_message(conn, {'status': 'authentication_failed', 'reason': 'signature_verification_failed'})
                return
                
            print(f"[✓] Client {client_name} authenticated successfully")
            
            # Check if all expected clients are connected
            if check_all_clients_connected():
                print(f"[✓] All expected clients connected: {', '.join(client_connections.keys())}")
                # Distribute certificates to all clients
                distribute_certificates()
                # Signal clients to start key exchange
                start_key_exchange()
            
            # Main message handling loop
            while True:
                msg = receive_framed_message(conn)
                if not msg:
                    print(f"[!] Client {client_name} disconnected")
                    break
                
                msg_type = msg.get('type')
                
                if msg_type == 'key_share':
                    # Client is sending an encrypted key share to a specific recipient
                    recipient = msg.get('recipient')
                    sender = msg.get('sender')
                    
                    if recipient and recipient in client_connections:
                        # Forward to specific recipient
                        send_framed_message(client_connections[recipient], msg)
                        print(f"[✓] Forwarded encrypted key share from {sender} to {recipient}")
                    else:
                        # Either missing recipient or recipient not connected
                        print(f"[!] Cannot forward key share: recipient={recipient}, connected={recipient in client_connections}")
                
                elif msg_type == 'group_chat':
                    # Forward encrypted chat message to all other clients
                    broadcast_message(msg, exclude=client_name)
                    print(f"[→] Forwarded encrypted chat message from {client_name}")
        
        except Exception as e:
            print(f"[!] Error processing client {addr}: {e}")
    
    finally:
        # Clean up client connection
        with lock:
            if client_name in client_connections:
                print(f"[-] Client {client_name} disconnected")
                client_connections.pop(client_name, None)
        
        conn.close()

def check_all_clients_connected():
    """Check if all expected clients (A, B, C) are connected."""
    with lock:
        connected_names = set(client_connections.keys())
        expected = {'A', 'B', 'C'}
        return expected.issubset(connected_names)

def distribute_certificates():
    """Send all client certificates to each client."""
    with lock:
        # Prepare certificates dict
        cert_dict = {}
        for name, cert in client_certs.items():
            cert_dict[name] = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        print(f"[*] Distributing certificates for: {', '.join(cert_dict.keys())}")
        
        # Send to each client
        for name, conn in client_connections.items():
            try:
                msg = {
                    'type': 'cert_distribution',
                    'certificates': cert_dict
                }
                send_framed_message(conn, msg)
                print(f"[✓] Sent certificates to {name}")
            except Exception as e:
                print(f"[!] Failed to send certificates to {name}: {e}")

def start_key_exchange():
    """Signal all clients to start key exchange."""
    with lock:
        print("[*] Signaling clients to start key exchange")
        
        # Signal all clients to start key exchange
        for name, conn in client_connections.items():
            try:
                msg = {
                    'type': 'start_key'
                }
                send_framed_message(conn, msg)
                print(f"[✓] Sent start_key signal to {name}")
            except Exception as e:
                print(f"[!] Failed to send start_key to {name}: {e}")

def broadcast_message(message, exclude=None):
    """Broadcast a message to all clients except the sender."""
    with lock:
        for name, conn in client_connections.items():
            if name != exclude:
                try:
                    send_framed_message(conn, message)
                    sender = message.get('sender', 'unknown')
                    print(f"[→] Message from {sender} forwarded to {name}")
                except Exception as e:
                    print(f"[!] Failed to send message to {name}: {e}")

def start_server():
    """Start the server and listen for connections."""
    global server_cert, server_key, root_ca_cert
    
    # Load server certificate and key
    try:
        server_cert = load_certificate("certificates/server_cert.pem")
        server_key = load_private_key("certificates/server_key.pem")
        root_ca_cert = load_root_ca_cert()
        print("[✓] Loaded server certificate, key, and Root CA certificate")
    except Exception as e:
        print(f"[✗] Failed to load server credentials: {e}")
        return
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(("127.0.0.1", 9999))
        server_socket.listen(5)
        print("[*] Server listening on 127.0.0.1:9999...")
        print("[*] Waiting for clients A, B, and C to connect...")
        
        # Accept connections
        while True:
            client_sock, client_addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_sock, client_addr),
                daemon=True
            )
            client_thread.start()
    
    except Exception as e:
        print(f"[!] Server error: {e}")
    
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()