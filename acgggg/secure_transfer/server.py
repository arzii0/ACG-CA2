"""Server program for receiving and storing secure records.

This file is the "server side" of the project.

Main idea:
1. Start a TLS 1.3 socket server.
2. Require the client to show a valid client certificate.
3. Receive signed messages/files.
4. Check SHA-256 integrity and RSA-PSS signature.
5. Store the record encrypted using AES-256-GCM.
6. Log every verification result to deployment/logs/server.log.
"""

# Task allocation - Yi Cheng:
# Implemented the TLS 1.3 server, mandatory client-certificate authentication,
# request routing, upload rejection, encrypted record storage, record
# verification/download controls, concurrency handling and verification audit
# logging. This file uses Remus's RSA-OAEP and RSA-PSS helpers and Rui Zhong's
# AES-GCM and SHA-256 helpers from crypto_utils.py.

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from secure_transfer.crypto_utils import (
    b64d,
    certificate_from_pem,
    certificate_to_pem,
    decrypt_from_storage,
    encrypt_for_storage,
    load_certificate,
    sha256_hex,
    verify_metadata_signature,
)
from secure_transfer.protocol import recv_json, send_json


class SecureStorageServer:
    # Yi Cheng (Role B - Server Program): implemented the TLS 1.3 server socket, the request
    # handling loop, digest/signature verification of uploads, encrypted at-rest storage of
    # records, and the verification audit log written to deployment/logs/.
    def __init__(self, host: str, port: int, base_dir: Path):
        # Server network location.
        self.host = host
        self.port = port

        # Main folders used by the server.
        self.base_dir = base_dir
        self.pki_dir = base_dir / "deployment" / "pki"
        self.storage_dir = base_dir / "storage" / "records"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Yi Cheng: audit log of every verification result. Each client is served on its own
        # thread, so a lock keeps concurrent log lines from interleaving.
        self.log_dir = base_dir / "deployment" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "server.log"
        self._log_lock = threading.Lock()

        # Server certificate is used for encrypted storage key wrapping.
        self.server_cert = load_certificate(self.pki_dir / "server.crt")

        # The server private-key password must be supplied through the environment.
        self.server_key_password = os.getenv("ACG_SERVER_KEY_PASSWORD")
        if not self.server_key_password:
            raise RuntimeError(
                "ACG_SERVER_KEY_PASSWORD is not set. "
                "Set it in the same terminal before starting the server."
            )

    # Yi Cheng (Role B): audit logging helpers.
    def _common_name(self, cert: x509.Certificate) -> str:
        """Read the Common Name out of a certificate subject."""

        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value if names else "unknown"

    def _log(
        self,
        event: str,
        outcome: str,
        record_id: str = "-",
        signer: str = "-",
        digest: str = "-",
        signature: str = "-",
    ) -> None:
        """Record one verification result on screen and in deployment/logs/server.log.

        Only metadata is logged (record id, signer, pass/fail). Message and file contents are
        never written here, otherwise the log would become a plaintext copy of the records that
        are deliberately encrypted at rest.
        """

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"{timestamp}  {event:<8} record={record_id:<32} signer={signer:<16} "
            f"digest={digest:<4} signature={signature:<4} -> {outcome}"
        )
        with self._log_lock:
            print(line, flush=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def serve_forever(self) -> None:
        """Start the TLS server and keep accepting clients."""

        # CLIENT_AUTH means the server is preparing to verify client certificates.
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Server certificate/key prove the server identity to the client.
        context.load_cert_chain(
            certfile=self.pki_dir / "server.crt",
            keyfile=self.pki_dir / "server.key",
            password=self.server_key_password,
        )

        # Trust only certificates signed by our local CA.
        context.load_verify_locations(cafile=self.pki_dir / "ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen()
            print(f"Secure storage server listening on {self.host}:{self.port}")
            while True:
                raw_sock, address = listener.accept()
                tls_sock = context.wrap_socket(raw_sock, server_side=True)
                # Each client request is handled in a thread so the server stays responsive.
                threading.Thread(target=self._handle_client, args=(tls_sock, address), daemon=True).start()

    def _handle_client(self, tls_sock: ssl.SSLSocket, address: tuple[str, int]) -> None:
        """Read one client command and return one JSON response."""

        with tls_sock:
            command = None
            record_id = "-"
            try:
                # This is the certificate the client presented during mutual TLS.
                peer_cert = x509.load_der_x509_certificate(tls_sock.getpeercert(binary_form=True))
                request = recv_json(tls_sock)
                command = request.get("command")
                record_id = str(request.get("record_id", "-")) or "-"
                if command == "upload":
                    response = self._upload(request, peer_cert)
                elif command == "list":
                    response = self._list()
                elif command == "download":
                    response = self._download(str(request.get("record_id", "")))
                elif command == "verify":
                    response = self._verify(str(request.get("record_id", "")))
                else:
                    response = {"ok": False, "error": f"Unknown command: {command}"}
            except Exception as exc:  # Keep demo server alive even if one request is malformed.
                # Yi Cheng: a record that fails to decrypt lands here (AES-GCM rejects modified
                # ciphertext), so this is the log entry that evidences tamper detection.
                self._log(
                    str(command).upper() if command else "REQUEST",
                    f"ERROR ({type(exc).__name__})",
                    record_id=record_id,
                )
                # InvalidTag and similar exceptions carry no message, so fall back to the
                # exception type. Otherwise the client just receives an empty error string.
                response = {"ok": False, "error": str(exc) or type(exc).__name__}
            send_json(tls_sock, response)

    def _upload(self, request: dict[str, Any], peer_cert: x509.Certificate) -> dict[str, Any]:
        """Validate and store one uploaded message/file."""

        metadata = request["metadata"]
        data = b64d(request["data_b64"])
        signature_b64 = request["signature_b64"]
        claimed_digest = metadata.get("sha256")
        signer = self._common_name(peer_cert)

        # Integrity check: recalculate SHA-256 and compare it to the client value.
        if claimed_digest != sha256_hex(data):
            self._log("UPLOAD", "REJECTED", signer=signer, digest="FAIL")
            return {"ok": False, "error": "SHA-256 digest does not match uploaded data"}

        # Non-repudiation check: verify the client's RSA-PSS signature using its certificate.
        if not verify_metadata_signature(peer_cert, metadata, signature_b64):
            self._log("UPLOAD", "REJECTED", signer=signer, digest="OK", signature="FAIL")
            return {"ok": False, "error": "Client signature is invalid"}

        # Store evidence: data, metadata, signature, and signer certificate.
        record_id = uuid.uuid4().hex
        package = {
            "record_id": record_id,
            "metadata": metadata,
            "data_b64": request["data_b64"],
            "signature_b64": signature_b64,
            "signer_certificate_pem": certificate_to_pem(peer_cert),
        }

        # Confidentiality at rest: the package is encrypted before writing to disk.
        envelope = encrypt_for_storage(self.server_cert, json.dumps(package, sort_keys=True).encode("utf-8"))
        (self.storage_dir / f"{record_id}.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        self._log("UPLOAD", "STORED", record_id=record_id, signer=signer, digest="OK", signature="OK")
        return {"ok": True, "record_id": record_id, "message": "Stored encrypted record with valid signature"}

    def _list(self) -> dict[str, Any]:
        """Return a summary of stored records."""

        records = []
        for path in sorted(self.storage_dir.glob("*.json")):
            try:
                package = self._open_package(path.stem)
                records.append(
                    {
                        "record_id": package["record_id"],
                        "sender": package["metadata"].get("sender"),
                        "name": package["metadata"].get("name"),
                        "kind": package["metadata"].get("kind"),
                        "size": package["metadata"].get("size"),
                        "created_at": package["metadata"].get("created_at"),
                        "sha256": package["metadata"].get("sha256"),
                    }
                )
            except Exception:
                records.append({"record_id": path.stem, "error": "Unable to decrypt or parse record"})
        return {"ok": True, "records": records}

    def _download(self, record_id: str) -> dict[str, Any]:
        """Return one record only if its hash and signature still verify."""

        package = self._open_package(record_id)
        verification = self._verify_package(package)
        self._log_verification("DOWNLOAD", record_id, verification, "RELEASED", "BLOCKED")
        if not verification["valid"]:
            return {"ok": False, "error": "Stored record failed verification", "verification": verification}
        return {
            "ok": True,
            "record_id": record_id,
            "metadata": package["metadata"],
            "data_b64": package["data_b64"],
            "verification": verification,
        }

    def _verify(self, record_id: str) -> dict[str, Any]:
        """Verify one stored record without downloading the data."""

        package = self._open_package(record_id)
        verification = self._verify_package(package)
        self._log_verification("VERIFY", record_id, verification, "VALID", "INVALID")
        return {"ok": True, "record_id": record_id, "verification": verification}

    def _log_verification(
        self,
        event: str,
        record_id: str,
        verification: dict[str, Any],
        pass_outcome: str,
        fail_outcome: str,
    ) -> None:
        """Yi Cheng (Role B): turn one verification result into an audit log entry."""

        self._log(
            event,
            pass_outcome if verification["valid"] else fail_outcome,
            record_id=record_id,
            signer=verification["signer"],
            digest="OK" if verification["digest_valid"] else "FAIL",
            signature="OK" if verification["signature_valid"] else "FAIL",
        )

    def _open_package(self, record_id: str) -> dict[str, Any]:
        """Decrypt one encrypted JSON file from storage/records."""

        path = self.storage_dir / f"{record_id}.json"
        if not path.exists():
            raise FileNotFoundError("Record does not exist")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        plaintext = decrypt_from_storage(self.pki_dir / "server.key", self.server_key_password, envelope)
        return json.loads(plaintext.decode("utf-8"))

    def _verify_package(self, package: dict[str, Any]) -> dict[str, Any]:
        """Check both integrity and non-repudiation for a decrypted record."""

        cert = certificate_from_pem(package["signer_certificate_pem"])
        metadata = package["metadata"]
        data = b64d(package["data_b64"])
        digest_valid = metadata.get("sha256") == sha256_hex(data)
        signature_valid = verify_metadata_signature(cert, metadata, package["signature_b64"])
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        signer = common_names[0].value if common_names else "unknown"
        return {
            "valid": digest_valid and signature_valid,
            "digest_valid": digest_valid,
            "signature_valid": signature_valid,
            "signer": signer,
            "signature_algorithm": "RSA-PSS-SHA256",
            "digest_algorithm": "SHA-256",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the secure storage server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--base-dir", default=".")
    args = parser.parse_args()
    SecureStorageServer(args.host, args.port, Path(args.base_dir).resolve()).serve_forever()


if __name__ == "__main__":
    main()
