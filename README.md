# Certificate Generation in Go using ed25519

This Go program generates a Public Key Infrastructure (PKI) chain consisting of:

- A **self-signed Root CA certificate**
- An **Intermediate CA certificate** signed by the Root
- A **Client certificate** signed by the Intermediate
- A **Server certificate** signed by the Intermediate

All certificates use **Ed25519** key pairs and follow the X.509 standard.

---

## Purpose

The program simulates a full PKI setup where:
- A Root CA signs an Intermediate CA.
- The Intermediate CA signs both a Client and a Server certificate.
- The generated certificates can be used in systems requiring cryptographically verifiable identities and TLS communication.

---

## 📁 Directory Structure
├── main.go
├── root.pem
├── intermediate.pem
├── client.pem
├── server.pem
└── keys/
├── privatekey.pem            # Root CA private key
├── interPrivateKey.pem       # Intermediate CA private key
├── clientPrivateKey.pem      # Client private key
└── serverPrivateKey.pem      # Server private key

>  Note: This script assumes that private keys for each entity are already generated and stored in `keys/` as PEM-encoded PKCS#8 files.

---

##  How It Works

1. **Read existing Ed25519 private keys** from the `keys/` directory.
2. **Decode the PEM blocks** using the `pem.Decode()` function.
3. **Parse the private keys** using `x509.ParsePKCS8PrivateKey()`.
4. **Create certificate templates** for each role (Root, Intermediate, Client, Server).
5. **Sign the certificates**:
   - Root signs its own certificate (self-signed).
   - Intermediate is signed by the Root.
   - Client and Server are both signed by the Intermediate.
6. **Write the certificates** to `.pem` files in the project root.

---

##  Dependencies

- Standard Go libraries only:
  - `crypto/x509`
  - `crypto/ed25519`
  - `encoding/pem`
  - `math/big`
  - `os`, `ioutil`, `time`, etc.

---

##  Usage

1. Ensure you have Go installed:  
   ```bash
   go version
   ```
2.	Place your private key files under ./keys:
	•	They must be in PEM-encoded PKCS#8 format.
3.	Run the program:
    ```bash
     go run main.go
    ```
    
4.	After successful execution, the following files will be generated:
  •	root.pem
  •	intermediate.pem
  •	client.pem
  •	server.pem
