ACG-CA2: SECURE FILE AND MESSAGE TRANSFER
=========================================
remus
Module: ST2504 Applied Cryptography
Assignment: Assignment 2

This application transfers text messages and files through a mutually
authenticated TLS connection. It also signs uploaded metadata and encrypts
records stored by the server.


1. REQUIREMENTS
===============

- Python 3.11 or newer
- PowerShell
- Internet access for the first package installation


2. INSTALLATION
===============

Open PowerShell in the project folder and install the dependencies:

    python -m pip install -r requirements.txt

Why:
The requirements file provides a repeatable installation process and ensures
that the required cryptography package is available.


3. PRIVATE-KEY PASSWORDS
========================

The following environment variables are required:

    ACG_CA_KEY_PASSWORD
    ACG_SERVER_KEY_PASSWORD
    ACG_CLIENT_KEY_PASSWORD

There is no hard-coded "changeit" fallback.

Recommended setup:

    .\Set-Strong-Key-Passwords.ps1

What the script does:

1. Generates separate strong random passwords for the CA, server and client.
2. Stores them in the current PowerShell process as environment variables.
3. Copies the client password temporarily to the Windows clipboard so it can
   be transferred to the second terminal.
4. Does not print the passwords or write them into the source code.

Why:
Hard-coded passwords can be exposed in source files, Git history and
screenshots. Cryptographically random passwords are difficult to predict, and
environment variables keep the secrets separate from the Python code.

Impact:
The private-key files remain encrypted. A person who obtains a key file still
needs its correct password to use it.


4. GENERATE THE PKI
===================

Run this in the same terminal:

    python -m secure_transfer.pki

This creates the CA, server and client certificates and encrypted RSA-3072
private keys inside:

    deployment\pki

Why:
The CA-signed certificates connect identities to public keys. They allow the
client and server to authenticate each other during mutual TLS.

Important:
Generate the PKI during initial setup only. Regenerating it replaces the server
RSA key. Existing records wrapped using the old server public key cannot be
unwrapped using the new server private key and will become unreadable.


5. RUN THE TESTS
================

Before the demonstration, run:

    python -m unittest discover -s tests -p "test_*.py" -v

Expected result:

    Ran ... tests
    OK

Why:
The tests provide repeatable evidence that the tested cryptographic and
password-management functions behave as expected. Tests reduce implementation
risk but do not prove that the application has no vulnerabilities.


6. START THE SERVER
===================

In Terminal 1, using the environment variables created earlier, run:

    python -m secure_transfer.server

Leave Terminal 1 running.

The server refuses to start if ACG_SERVER_KEY_PASSWORD is missing or incorrect.


7. PREPARE TERMINAL 2
=====================

Open a second PowerShell terminal and enter the project folder:

    cd "C:\Users\remus\Downloads\ACG-CA2-FRESH"

Load the client password copied by the setup script:

    $env:ACG_CLIENT_KEY_PASSWORD = (Get-Clipboard).Trim()

Confirm that a value was loaded without displaying it:

    $env:ACG_CLIENT_KEY_PASSWORD.Length

Clear the clipboard without revealing the password:

    Set-Clipboard -Value "CLEARED"

Why:
Terminal 2 is a separate process and does not automatically receive the
process-level variables from Terminal 1. The correct client password is needed
to decrypt client.key for TLS authentication and RSA-PSS signing.


8. CLIENT COMMANDS
==================

Send a text message:

    python -m secure_transfer.client send-message --message "Testing secure transfer."

Send a file:

    python -m secure_transfer.client send-file --path .\original_message.txt

List records:

    python -m secure_transfer.client list

Verify a record:

    python -m secure_transfer.client verify --record-id YOUR_RECORD_ID

Download a record:

    python -m secure_transfer.client download --record-id YOUR_RECORD_ID --out downloaded_message.txt

Demonstrate rejection of tampered signed metadata:

    python -m secure_transfer.client tamper-signature-demo --message "Original signed message"

Replace YOUR_RECORD_ID with the record_id returned by send-message or
send-file.


9. EXPECTED OUTPUTS
===================

A successful upload returns JSON containing:

    "ok": true
    "record_id": "..."

A successful verification should show:

    "digest_valid": true
    "signature_valid": true
    "valid": true

Meaning:

- digest_valid confirms that the record content matches its SHA-256 hash.
- signature_valid confirms that its RSA-PSS signature is valid.
- valid is true only when both checks succeed.


10. COMPLETE DEMONSTRATION AND SPEAKING GUIDE
=============================================

Use a clean copy of the exact ZIP intended for submission. Do not regenerate
the PKI after records have been uploaded.


STEP 1 - Prepare Terminal 1
---------------------------

    cd "C:\Users\remus\Downloads\ACG-CA2-FRESH"

    python -m pip install -r requirements.txt

    .\Set-Strong-Key-Passwords.ps1

    [Environment]::SetEnvironmentVariable("ACG_CLIENT_KEY_PASSWORD", $env:ACG_CLIENT_KEY_PASSWORD, "User")

What to explain:
The dependencies are installed from one requirements file so the project can
be reproduced on another computer. The password script uses a
cryptographically secure random-number generator and keeps passwords outside
the source code.

Security impact:
Private keys are not protected by predictable or hard-coded passwords.
Passwords must not be displayed in the terminal or included in screenshots.


STEP 2 - Generate the certificates and keys
-------------------------------------------

    python -m secure_transfer.pki

What to explain:
The command creates the CA, client and server certificates and encrypted
RSA-3072 private keys. The CA signs the client and server certificates, which
allows their public keys and identities to be trusted during mutual TLS.

Security impact:
The client can authenticate the server, and the server can authenticate the
client. Running this command again replaces the keys, so existing records may
become unreadable.


STEP 3 - Run the automated tests
--------------------------------

    python -m unittest discover -s tests -p "test_*.py" -v

What to explain:
The tests give repeatable evidence that the tested cryptographic and
password-management functions work correctly.

Expected result:

    Ran ... tests
    OK

Only state the number of passing tests shown by the actual output.


STEP 4 - Start the server
-------------------------

    python -m secure_transfer.server

Leave Terminal 1 running.

What to explain:
The server loads its encrypted private key and waits for mutually authenticated
TLS connections. TLS protects information while it travels across the network.

Security impact:
An untrusted client certificate should be rejected, and the client should
reject an untrusted server certificate.


STEP 5 - Prepare Terminal 2
---------------------------

    cd "C:\Users\remus\Downloads\ACG-CA2-FRESH"

    $env:ACG_CLIENT_KEY_PASSWORD = [Environment]::GetEnvironmentVariable("ACG_CLIENT_KEY_PASSWORD", "User")

    $env:ACG_CLIENT_KEY_PASSWORD.Length

What to explain:
Terminal 2 is a separate process, so the client password must be loaded into
it. Displaying only the length confirms that a value exists without revealing
the password.

Security impact:
The password unlocks client.key for client-certificate authentication and
RSA-PSS signing. An incorrect password causes private-key loading to fail.


STEP 6 - Show the initial server state
--------------------------------------

    python -m secure_transfer.client list

What to explain:
This checks the complete client-to-server connection before uploading. In a
clean demonstration, the records list should be empty.

Security impact:
A successful request confirms that the certificates, private keys, passwords,
TLS connection and application protocol are working together.


STEP 7 - Upload one text message
--------------------------------

    $messageResult = python -m secure_transfer.client send-message --message "Testing secure message transfer." | ConvertFrom-Json

    $messageRecordId = $messageResult.record_id

    $messageResult

    "Message record ID: $messageRecordId"

What to explain:
The client converts the message into bytes, calculates its SHA-256 hash and
signs metadata containing that hash with RSA-PSS. The server returns a unique
record ID.

Security impact:
SHA-256 detects content changes. RSA-PSS also authenticates the signed metadata
because only the holder of the client private key should be able to create a
valid signature.

Record this message record ID as demonstration evidence.


STEP 8 - Create and hash one file
---------------------------------

For a real binary-file demonstration, place a small PNG or PDF in the project
folder and replace demo_file.png below with its filename.

    $filePath = ".\demo_file.png"

    $clientHash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLowerInvariant()

    "Original file hash: $clientHash"

If a binary file is unavailable, create the following controlled text file:

    [System.IO.File]::WriteAllText("$PWD\original_message.txt", "Testing secure key generation and transfer.", [System.Text.UTF8Encoding]::new($false))

    $filePath = ".\original_message.txt"

    $clientHash = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLowerInvariant()

What to explain:
The hash is calculated before upload, so it becomes the trusted reference value
for the later comparison. Hashes operate on the exact bytes, not merely the
visible filename or text.

Security impact:
Changing even one byte should produce a different SHA-256 result. SHA-256 alone
does not identify the sender, so the hash is also placed inside RSA-PSS-signed
metadata.


STEP 9 - Upload the file and capture its record ID
--------------------------------------------------

    $uploadResult = python -m secure_transfer.client send-file --path $filePath | ConvertFrom-Json

    $recordId = $uploadResult.record_id

    $uploadResult

    "File record ID: $recordId"

What to explain:
The unique record ID identifies this specific stored record. It is safer and
more precise than selecting a record only by filename.

Security impact:
The signed metadata binds the sender information, filename and SHA-256 content
hash together. Modifying signed information should invalidate the signature.

Record this file record ID as demonstration evidence.


STEP 10 - List the records and obtain the stored hash
-----------------------------------------------------

    $listResult = python -m secure_transfer.client list | ConvertFrom-Json

    $listResult.records | Format-Table record_id, sender, name, size, sha256

    $serverHash = ($listResult.records | Where-Object { $_.record_id -eq $recordId }).sha256

    "Server stored hash: $serverHash"

What to explain:
The record is selected by its ID, and its signed metadata hash is extracted for
comparison with the original client hash.

Security impact:
This provides evidence that the server metadata refers to the same content that
was hashed by the client before upload.


STEP 11 - Verify the file record
--------------------------------

    python -m secure_transfer.client verify --record-id $recordId

Expected result:

    "digest_valid": true
    "signature_valid": true
    "valid": true

What to explain:

- digest_valid means the stored content matches the SHA-256 value in metadata.
- signature_valid means the RSA-PSS signature is valid for that metadata.
- valid becomes true only when both checks succeed.

Security impact:
Changing the content, signed metadata or signature should cause verification to
fail rather than allowing a damaged or forged record to be trusted.


STEP 12 - Download the file
---------------------------

Use an output filename with the same file type as the uploaded file:

    $downloadPath = ".\downloaded_demo_file.png"

    python -m secure_transfer.client download --record-id $recordId --out $downloadPath

For the text-file fallback, use:

    $downloadPath = ".\downloaded_message.txt"

    python -m secure_transfer.client download --record-id $recordId --out $downloadPath

    Get-Content $downloadPath

What to explain:
The output is saved under a different name so the original file is not
overwritten and both files remain available for independent comparison.

Security impact:
The server must first recover the AES key and decrypt the stored record. A
damaged AES-GCM ciphertext or authentication tag should cause decryption to
fail.


STEP 13 - Compare the original, server and downloaded hashes
------------------------------------------------------------

    $downloadedHash = (Get-FileHash $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()

    "Client original hash: $clientHash"

    "Server stored hash:   $serverHash"

    "Downloaded hash:      $downloadedHash"

    "Client matches server:     $($clientHash -eq $serverHash)"

    "Client matches downloaded: $($clientHash -eq $downloadedHash)"

Expected result:

    Client matches server:     True
    Client matches downloaded: True

What to explain:
The first True result confirms that the signed server metadata contains the
original hash. The second True result confirms that the downloaded file is
byte-for-byte identical to the original.

Security impact:
This gives end-to-end integrity evidence covering the original file, uploaded
record, server metadata and downloaded file.


STEP 14 - Explain the hybrid-encryption design
----------------------------------------------

Suggested explanation:

The stored record is encrypted with AES-256-GCM because AES is efficient for
files and GCM detects unauthorised ciphertext modification. The random AES key
is wrapped using RSA-OAEP and the server public key. Only the matching server
private key can unwrap it. RSA encrypts only the small AES key because RSA has
message-size limits and is inefficient for complete files. This combination of
RSA and AES is called hybrid encryption.


STEP 15 - Demonstrate RSA-PSS tampering detection
-------------------------------------------------

Run this in Terminal 2 while the server is running:

    python -m secure_transfer.client tamper-signature-demo --message "Original signed message"

Expected result:

    "ok": false
    "error": "Client signature is invalid"

What the command does:

1. Creates metadata containing the message name and SHA-256 content hash.
2. Signs the original metadata using the client RSA private key and RSA-PSS.
3. Deliberately changes the signed name from original-message.txt to
   tampered-message.txt after the signature has been created.
4. Sends the changed metadata together with the old signature.
5. The server verifies the signature using the client public key and rejects
   the upload.

Why the verification fails:
An RSA-PSS signature is calculated from the exact canonical metadata bytes.
Changing even one signed field changes those bytes. The original signature
therefore cannot be valid for the modified metadata.

Security impact:
The server does not store the rejected record. This demonstrates that an
attacker cannot silently change signed metadata and continue using the original
signature. The demonstration does not damage or edit an existing valid record.

Suggested explanation:
The client first signed original metadata with its private key. For this
controlled negative test, the filename was changed after signing. The server
recreated the signed bytes and checked the signature using the public key in
the client certificate. Because the metadata no longer matched, RSA-PSS
verification failed and the server rejected the upload.


STEP 16 - Optional client password rotation
-------------------------------------------

    .\Change-Client-Password.ps1

    python -m secure_transfer.client list

    python -m secure_transfer.client verify --record-id $recordId

What to explain:
The helper generates a new password and re-encrypts the same client private key.
It does not generate a new RSA key pair or certificate.

Security impact:
The old password can no longer unlock client.key, while the existing
certificate remains usable because the underlying RSA key has not changed.


STEP 17 - Clean up after the demonstration
------------------------------------------

    [Environment]::SetEnvironmentVariable("ACG_CLIENT_KEY_PASSWORD", $null, "User")

    Remove-Item Env:ACG_CLIENT_KEY_PASSWORD -ErrorAction SilentlyContinue

What to explain:
The saved variable is removed because secrets should remain accessible only
while required.

Security impact:
This reduces the chance that a later terminal session or user accidentally
reuses or exposes the client private-key password.


DEMONSTRATION EVIDENCE CHECKLIST
--------------------------------

Capture readable screenshots showing:

- Successful automated tests.
- Successful server start without revealing passwords.
- One uploaded text message and its record ID.
- One uploaded file and its record ID.
- The list output containing both records.
- Verification showing digest_valid, signature_valid and valid as true.
- Rejected tampering demonstration showing "Client signature is invalid".
- Successful file download.
- The three SHA-256 values and both comparisons returning True.

Never capture passwords, clipboard contents, private-key contents or the CA
private key in screenshots.


11. CHANGE THE CLIENT KEY PASSWORD
==================================

Run this in the client terminal:

    .\Change-Client-Password.ps1

Then confirm that the client still works:

    python -m secure_transfer.client list
    python -m secure_transfer.client verify --record-id YOUR_RECORD_ID

The helper:

1. Uses ACG_CLIENT_KEY_PASSWORD to unlock client.key.
2. Generates a new cryptographically strong password.
3. Re-encrypts client.key using the new password.
4. Updates ACG_CLIENT_KEY_PASSWORD in the current PowerShell terminal.
5. Does not display the new password.

Why:
Password rotation replaces the protection around the private-key file if the
old password is outdated or suspected of exposure.

Impact:
The RSA key pair and client certificate do not change, so the existing
certificate remains usable. Only the password-based encryption protecting
client.key changes.


12. HOW THE SECURITY DESIGN WORKS
=================================

The application combines several controls because no single algorithm provides
confidentiality, integrity, authentication, key distribution and efficient file
encryption by itself.


SHA-256 - content fingerprint
-----------------------------

What it does:
SHA-256 converts content of any size into a fixed 256-bit digest. A small
content change should result in a different digest.

Why it is used:
It provides a compact value that can be signed and compared instead of placing
the complete file inside the RSA signature operation.

Impact:
The application can detect accidental corruption or deliberate content
modification.

Limitation:
SHA-256 does not authenticate the sender. Anyone can change a file and
calculate a new hash. RSA-PSS is therefore required to sign metadata containing
the hash.


RSA-PSS - digital signature
---------------------------

What it does:
The client uses its RSA private key to sign metadata containing fields such as
the sender, filename and SHA-256 content hash. The server verifies the
signature using the RSA public key from the client certificate.

Why RSA-PSS is used:
RSA-PSS is designed for digital signatures and includes randomized padding.
Signing the same data twice can produce different valid signatures. This is
safer than textbook RSA and avoids the predictable structure of directly
applying RSA to a hash.

Why the private and public keys are used this way:
Only the client should control its private key, so only that client should be
able to create its signature. The public key can be distributed in the
certificate so the server can verify the signature without learning the
private key.

Impact:
RSA-PSS provides:

- Authentication: evidence that the matching client private key was used.
- Integrity: modification of signed metadata causes verification to fail.
- Accountability: the signature can be linked to the certificate identity when
  the private key is properly controlled.

Limitation:
A signature supports non-repudiation only if the certificate identity is
trustworthy and the private key has not been shared, stolen or misused.


AES-256-GCM - stored-record encryption
--------------------------------------

What it does:
AES encrypts the complete stored record using a random 256-bit key. GCM mode
also calculates an authentication tag.

Why AES is used:
AES is a fast symmetric algorithm suitable for messages and files of different
sizes. It is much more efficient for bulk data than RSA.

Why GCM is used:
Encryption alone hides information but may not detect modification. GCM is an
authenticated-encryption mode, so it provides confidentiality and ciphertext
integrity together.

Impact:

- Someone reading the storage directory cannot understand the plaintext
  without the AES key.
- Changing the ciphertext, nonce, authenticated data or authentication tag
  causes AES-GCM decryption to fail.
- A separate random AES key can protect each record, limiting the effect of one
  record key being compromised.

Important:
A nonce must not be reused with the same AES-GCM key. The application generates
a new random key and nonce for each protected record.


RSA-OAEP - AES key wrapping
---------------------------

What it does:
RSA-OAEP encrypts, or "wraps", the small random AES key using the server public
key. The server uses its matching RSA private key to decrypt, or "unwrap", that
AES key before using AES-GCM to decrypt the record.

Why RSA-OAEP is used:
The AES key must be protected before it is stored. The server public key can be
used for wrapping without exposing the server private key. OAEP adds randomized
padding, so encrypting the same input more than once should produce different
ciphertext.

Why RSA does not encrypt the complete file:
RSA has a strict input-size limit and is slow compared with AES. With
RSA-3072 and OAEP-SHA256, only a small amount of data can be encrypted in one
operation. A 32-byte AES-256 key fits comfortably, while a normal file may not.

Impact:
Only someone with the matching server private key can recover the stored AES
key. This protects the AES key even when the wrapped key and encrypted record
are visible in storage.

Terminology:
Protecting the AES key with RSA-OAEP is called key wrapping. Recovering it with
the RSA private key is called key unwrapping.


Why RSA-PSS and RSA-OAEP are both needed
----------------------------------------

They use RSA for different purposes and are not interchangeable:

- RSA-PSS is a signature scheme. It proves that signed metadata matches the
  holder of a private key.
- RSA-OAEP is an encryption scheme. It keeps the AES key confidential.

RSA-PSS does not encrypt the record, and RSA-OAEP does not prove that the
client signed the metadata.


Mutual TLS - protection during transmission
-------------------------------------------

What it does:
TLS encrypts network traffic. Mutual TLS additionally requires both the server
and client to present CA-signed certificates.

Why it is used:
Stored-record encryption protects data at rest, but it does not protect live
requests travelling across the network. Mutual TLS protects that separate
stage and authenticates both endpoints.

Impact:

- An observer should not be able to read the transferred data.
- The client can reject a server with an untrusted certificate.
- The server can reject a client with an untrusted certificate.
- Certificate validation reduces server and client impersonation risks.


HYBRID-ENCRYPTION SUMMARY
-------------------------

The complete protection process is:

1. SHA-256 creates a fingerprint of the uploaded content.
2. RSA-PSS signs metadata containing that fingerprint.
3. AES-256-GCM encrypts and authenticates the complete stored record.
4. RSA-OAEP wraps the small AES key using the server public key.
5. Mutual TLS protects and authenticates the network connection.

Each control has a separate purpose:

    SHA-256       -> content integrity check
    RSA-PSS       -> signature and client authentication
    AES-256-GCM   -> efficient authenticated record encryption
    RSA-OAEP      -> AES-key confidentiality
    Mutual TLS    -> encrypted and mutually authenticated transport

This is called a defence-in-depth design. If one layer addresses only one
security problem, the other layers provide the additional properties needed by
the complete system.


13. COMMON ERRORS
=================

Error: "Incorrect password, could not decrypt key" or "PEM lib"

Cause:
ACG_CLIENT_KEY_PASSWORD or ACG_SERVER_KEY_PASSWORD does not match the password
used when the corresponding key was generated.

Fix:
Load the correct environment variable. Do not regenerate the PKI merely to fix
a password mismatch if existing records must be retained.


Error: "Unable to decrypt or parse record"

Cause:
The record was probably encrypted using an older server RSA key, or its stored
data was damaged.

Fix:
Restore the matching original server key. For a fresh demonstration, back up
the old records and create new records using the current PKI.


Error: "No module named cryptography"

Fix:

    python -m pip install -r requirements.txt


Error: client cannot connect

Check:

- Terminal 1 is still running the server.
- The client and server are using certificates from the same PKI.
- The required password variables are loaded.
- The configured host and port match.


14. CLEANUP AFTER THE DEMONSTRATION
===================================

Remove the saved client password from the user environment and current process:

    [Environment]::SetEnvironmentVariable("ACG_CLIENT_KEY_PASSWORD", $null, "User")

    Remove-Item Env:ACG_CLIENT_KEY_PASSWORD -ErrorAction SilentlyContinue

Why:
Secrets should remain available only as long as required. Removing the variable
reduces the chance of accidental reuse or exposure.


15. IMPORTANT SECURITY NOTES
============================

- Never commit passwords, private keys or secret-containing .env files.
- Never show passwords or private-key contents in screenshots.
- Environment variables created only in a process must be set again in a new
  terminal.
- Back up important private keys securely before changing their passwords.
- Changing a key-file password does not require a new certificate.
- Do not regenerate the server key if existing encrypted records must remain
  accessible.
- A digital signature supports non-repudiation only when the certificate
  identity is trustworthy and the private key remains under the owner's
  exclusive control.
