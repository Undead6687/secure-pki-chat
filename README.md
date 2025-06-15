# 🔐 Secure Chat System with PKI Authentication

A secure chat system which implements PKI (Public Key Infrastructure) authentication, certificate-based client verification, and encrypted group messaging using a hybrid encryption approach.

## 📌 Features

- **PKI Authentication**: Root CA-based certificate generation and validation  
- **Mutual Authentication**: Server and client certificate verification  
- **Secure Key Exchange**: Distributed key contribution system with RSA encryption  
- **Group Encryption**: AES-GCM with HKDF key derivation for chat messages  
- **Certificate Management**: Automatic certificate generation and distribution  
- **Message Integrity**: HMAC verification for all encrypted messages  
- **Multi-threaded Server**: Handles multiple concurrent client connections  

## 🏗️ Architecture

### Components

1. **Root CA (`root_ca.py`)**: Generates and manages certificates for all entities  
2. **Server (`server.py`)**: Authenticates clients and facilitates secure communication  
3. **Client (`client.py`)**: Connects to server, participates in key exchange, and sends/receives encrypted messages  
4. **Authentication Utils (`auth_utils.py`)**: Certificate verification and cryptographic operations  
5. **Encryption Utils (`encryption_utils.py`)**: Message encryption/decryption and key derivation  

### Security Features

- **4096-bit RSA** keys for Root CA  
- **2048-bit RSA** keys for clients and server  
- **AES-256-GCM** for message encryption  
- **HKDF** (HMAC-based Key Derivation Function) for group key generation  
- **HMAC-SHA256** for message integrity  
- **Certificate chain validation**  

## 🚀 Quick Start

### Prerequisites

- Python 3.8+  
- pip package manager  

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd secure-chat-system
   ```

2. **Create virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Setup & Usage

1. **Generate certificates:**
   ```bash
   python root_ca.py
   ```
   This creates a `certificates/` directory with:
   - Root CA certificate and private key  
   - Server certificate and private key  
   - Client certificates and private keys for clients A, B, and C  

2. **Start the server:**
   ```bash
   python server.py
   ```
   The server will listen on `127.0.0.1:9999` and wait for clients to connect.

3. **Start clients (in separate terminals):**
   ```bash
   python client.py
   # Enter client name: A (or B, or C)
   ```
   Repeat for each client (A, B, C). The system requires all three clients to be connected before starting the secure chat.

> **Tip**: To exit the application at any time, type `exit` (without quotes).

## 🔄 Protocol Flow

### Detailed Protocol Description with Specified Algorithms

#### Phase 1: Authentication (Using RSA)

1. *Entity A authenticates to Server S*:
   ```
   A → S: CA⟨⟨A⟩⟩, N_A
   ```
   - A sends its certificate and a fresh nonce to S  
   ```
   S → A: CA⟨⟨S⟩⟩, N_S, Sign_S(N_A)
   ```
   - S sends its certificate, a fresh nonce, and signs both nonces with its private key  
   ```
   A → S: Sign_A(N_S)
   ```
   - A signs S's nonce to complete authentication  
   - This establishes secure channels and temporary session keys (`K_AS`, `K_BS`, `K_CS`) derived from the nonces

2. *Similar authentication exchanges occur between B and S, and C and S*

---

#### Phase 2: Certificate Distribution

1. *Server distributes certificates*:
   ```
   S → A: {CA⟨⟨B⟩⟩, CA⟨⟨C⟩⟩}_AES-GCM_K_AS + Sign_S(Hash(CA⟨⟨B⟩⟩, CA⟨⟨C⟩⟩))
   ```
   - S sends B's and C's certificates to A, encrypted with AES-256-GCM  
   - S also signs the hash of the certificates to ensure integrity

   ```
   S → B: {CA⟨⟨A⟩⟩, CA⟨⟨C⟩⟩}_AES-GCM_K_BS + Sign_S(Hash(CA⟨⟨A⟩⟩, CA⟨⟨C⟩⟩))
   ```
   - S sends A's and C's certificates to B

   ```
   S → C: {CA⟨⟨A⟩⟩, CA⟨⟨B⟩⟩}_AES-GCM_K_CS + Sign_S(Hash(CA⟨⟨A⟩⟩, CA⟨⟨B⟩⟩))
   ```
   - S sends A's and B's certificates to C

---

#### Phase 3: Key Contribution

1. *Entity A contributes its key component*:
   ```
   A → S: {k_A}_RSA_PK_B, {k_A}_RSA_PK_C + Sign_A(Hash(MSG))
   ```
   - A encrypts its key contribution with B's and C's public keys  
   - A signs the hash of the entire message for integrity

   ```
   S → B: {k_A}_RSA_PK_B + Sign_S(Hash(MSG))
   ```
   - S forwards A's contribution to B

   ```
   S → C: {k_A}_RSA_PK_C + Sign_S(Hash(MSG))
   ```
   - S forwards A's contribution to C

2. *Similar key contribution exchanges occur for B's and C's contributions*

---

#### Phase 4: Session Key Derivation (Using HKDF)

1. *Each entity derives the shared session key*:
   ```text
   K_abc = HKDF(k_A || k_B || k_C)
   ```
   - HKDF is the HMAC-based Key Derivation Function  
   - `||` represents concatenation of the key components

---

### Secure Chat

Once the session key `K_abc` is established, all chat messages are encrypted using AES-256-GCM with `K_abc` as the key:

```text
A → S → B,C: {M1}_AES-GCM_K_abc + Sign_A(Hash(M1))
B → S → A,C: {M2}_AES-GCM_K_abc + Sign_B(Hash(M2))
C → S → A,B: {M3}_AES-GCM_K_abc + Sign_C(Hash(M3))
```

## 🛡️ Security Properties

1. **Authentication**: RSA signatures with certificates ensure that all parties are properly authenticated.

2. **Confidentiality**:
   - AES-256-GCM provides strong encryption for all sensitive data  
   - RSA encryption protects the key components during exchange

3. **Integrity**:
   - Digital signatures (RSA-based) verify the integrity of all messages  
   - Hash functions (SHA-256) provide message digests for signing

4. **Key Agreement**:
   - Each party contributes to the final key  
   - HKDF ensures a strong derivation of the final session key

5. **End-to-End Encryption**:
   - Server S cannot access the final session key `K_abc`  
   - Server S only forwards encrypted messages between parties

## 📁 File Structure

```plaintext
secure-chat-system/
├── root_ca.py              # Root CA certificate generation
├── server.py               # Multi-threaded secure server
├── client.py               # Secure chat client
├── auth_utils.py           # Authentication utilities
├── encryption_utils.py     # Encryption/decryption utilities
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── certificates/           # Generated certificates (created by root_ca.py)
    ├── root_ca_cert.pem
    ├── root_ca_key.pem
    ├── server_cert.pem
    ├── server_key.pem
    ├── A_cert.pem
    ├── A_key.pem
    ├── B_cert.pem
    ├── B_key.pem
    ├── C_cert.pem
    └── C_key.pem
```

## 🧪 Testing

1. **Single Machine Testing:**
   ```bash
   python server.py   # Run server in one terminal
   python client.py   # Run three clients in separate terminals
   ```

2. **Network Testing:**
   ```bash
   Modify server binding address in server.py
   Update client connection address in client.py
   Ensure firewall allows connections on port 9999
   ```

## Implementation Considerations

For your assignment implementation, you could:

1. **Libraries to use**:
   - OpenSSL or similar for RSA, AES-256-GCM, and HKDF operations  
   - A socket programming library for network communication

2. **Authentication implementation**:
   - Generate RSA key pairs and certificates for each entity  
   - Use X.509 certificate validation

3. **Encryption implementation**:
   - Use AES-256-GCM with random initialization vectors (IVs)  
   - Ensure proper key handling

4. **Message integrity**:
   - Use SHA-256 for hashing before signing  
   - Validate signatures on receipt

5. **Socket communication**:
   - Implement reliable message passing between entities through the server

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.


## ⚠️ Disclaimer

This implementation is for educational and research purposes. While it implements industry-standard cryptographic practices, it should undergo thorough security review before use in production environments.

---

> Made with ❤️ by Miran Shaikh
