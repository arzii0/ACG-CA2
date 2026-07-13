# ACG-CA2
ACG Assignment CA2
ST2504 Applied Cryptography Assignment 2  
Secure File and Message Transfer Application

Requirements

- Python 3.11 or newer
- Internet access for first-time package installation

Setup

1. Open PowerShell in the project base folder:

   cd "C:\ACG\ACG CA2\ACG-CA2"

2. Install required Python packages:

   python -m pip install -r requirements.txt

3. Set passwords for the encrypted private keys. Replace the example passwords with your own strong demo passwords:

   $env:ACG_CA_KEY_PASSWORD = "your-CA-password"
   $env:ACG_SERVER_KEY_PASSWORD = "your-server-password"
   $env:ACG_CLIENT_KEY_PASSWORD = "your-client-password"

4. Generate the Certificate Authority (CA), server, and client keys/certificates:

   python -m secure_transfer.pki

The generated key material is saved in deployment\pki\.

Running the Server

Open a PowerShell terminal in the project base folder and run:

   $env:ACG_SERVER_KEY_PASSWORD = "your-server-password"
   python -m secure_transfer.server

The server listens on 127.0.0.1:8443.

Running the Client

Open a second PowerShell terminal in the project base folder and run:

   $env:ACG_CLIENT_KEY_PASSWORD = "your-client-password"
   python -m secure_transfer.client send-message --message "This is a secure message."

The program returns a record_id after a successful upload.

Client Commands

List stored records:

   python -m secure_transfer.client list

Verify a stored record. Replace RECORD_ID with the returned record ID:

   python -m secure_transfer.client verify --record-id RECORD_ID

Download a verified record:

   python -m secure_transfer.client download --record-id RECORD_ID --out downloaded_message.txt

Send a file:

   python -m secure_transfer.client send-file --path "path\to\file.txt"

Security Features

- RSA-3072 key pairs for the CA, client, and server.
- Private keys are stored as password-encrypted PEM files.
- Passwords are supplied through environment variables instead of hard-coded in the source code.
- CA-signed server and client certificates support mutual TLS.
- TLS 1.3 protects data confidentiality and integrity during transmission.
- RSA-PSS with SHA-256 provides message integrity and non-repudiation.
- AES-256-GCM encrypts stored records at rest.

Notes

- Use the same client/server passwords that were used when generating the keys.
- Environment-variable passwords are temporary and must be set again after opening a new PowerShell terminal.
- Regenerating the server key prevents old encrypted records from being decrypted. For a clean demo, regenerate keys before storing new records.