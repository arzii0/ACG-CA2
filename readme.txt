# ACG-CA2
ACG Assignment CA2
ST2504 Applied Cryptography Assignment 2  
Secure File and Message Transfer Application

Requirements

- Python 3.11 or newer
- Internet access for first-time package installation

Setup

1. Install dependencies:

   cd "C:\ACG\ACG CA2\ACG-CA2"

   python -m pip install -r requirements.txt

2. Terminal 1 — generate keys and start server

   cd "C:\ACG\ACG CA2\ACG-CA2"

   $env:ACG_CA_KEY_PASSWORD = "your-CA-password"

   $env:ACG_SERVER_KEY_PASSWORD = "your-server-password"

   $env:ACG_CLIENT_KEY_PASSWORD = "your-client-password"

   python -m secure_transfer.pki

   python -m secure_transfer.server

3. Terminal 2 — send and verify

   cd "C:\ACG\ACG CA2\ACG-CA2" 
   
   $env:ACG_CLIENT_KEY_PASSWORD = "your-client-password"

   python -m secure_transfer.client send-message --message "Testing secure transfer."

Copy the returned record_id, then run:

   python -m secure_transfer.client list

   python -m secure_transfer.client verify --record-id YOUR_RECORD_ID
   
   python -m secure_transfer.client download --record-id YOUR_RECORD_ID --out downloaded_message.txt
   
   Get-Content downloaded_message.txt

Security Features

- RSA-3072 key pairs for the CA, client, and server.
- Private keys are stored as password-encrypted PEM files.
- PKI key-generation passwords are supplied through environment variables instead of being hard-coded in pki.py.
- CA-signed server and client certificates support mutual TLS.
- TLS 1.3 protects data confidentiality and integrity during transmission.
- RSA-PSS with SHA-256 provides message integrity and non-repudiation.
- AES-256-GCM encrypts stored records at rest.

Notes

- Use the same client/server passwords that were used when generating the keys.
- Environment-variable passwords are temporary and must be set again after opening a new PowerShell terminal.
- Regenerating the server key prevents old encrypted records from being decrypted. For a clean demo, regenerate keys before storing new records.