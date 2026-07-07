"""Client program for sending secure messages or files.

This file is the "client side" of the project.

Main idea:
1. Build the message/file metadata.
2. Hash the data with SHA-256.
3. Sign the metadata with the client's private key.
4. Send everything to the server through mutual TLS.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secure_transfer.crypto_utils import b64e, sha256_hex, sign_metadata
from secure_transfer.protocol import recv_json, send_json


class SecureTransferClient:
    # Student contribution: this client signs transfer metadata before upload so the server can
    # prove who submitted a stored message or file during the demo.
    def __init__(self, host: str, port: int, base_dir: Path):
        # Server network location.
        self.host = host
        self.port = port

        # All certs and keys are stored under deployment/pki.
        self.base_dir = base_dir
        self.pki_dir = base_dir / "deployment" / "pki"

        # Default password is for demo only. In a real system this should be a secret.
        self.client_key_password = os.getenv("ACG_CLIENT_KEY_PASSWORD", "changeit")

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON request to the server using mutual TLS."""

        # The CA certificate lets the client check that it is talking to the real server.
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.pki_dir / "ca.crt")

        # The client certificate proves the client's identity to the server.
        context.load_cert_chain(
            certfile=self.pki_dir / "client.crt",
            keyfile=self.pki_dir / "client.key",
            password=self.client_key_password,
        )

        # TLS 1.3 provides confidentiality and integrity while data is travelling.
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        with socket.create_connection((self.host, self.port), timeout=10) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                send_json(tls_sock, payload)
                return recv_json(tls_sock)

    def upload(self, kind: str, name: str, sender: str, data: bytes) -> dict[str, Any]:
        """Prepare and upload a signed message/file."""

        # Metadata describes the transfer. The SHA-256 value proves the content has not changed.
        metadata = {
            "kind": kind,
            "name": name,
            "sender": sender,
            "size": len(data),
            "sha256": sha256_hex(data),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # The client signs the metadata. Because the metadata includes the SHA-256 hash,
        # the signature is also tied to the exact data being sent.
        signature_b64 = sign_metadata(self.pki_dir / "client.key", self.client_key_password, metadata)

        # Bytes cannot be placed directly inside JSON, so the file/message is base64 encoded.
        return self.request(
            {
                "command": "upload",
                "metadata": metadata,
                "data_b64": b64e(data),
                "signature_b64": signature_b64,
            }
        )


def _print_response(response: dict[str, Any]) -> None:
    print(json.dumps(response, indent=2, sort_keys=True))


def main() -> None:
    # argparse creates the command-line interface, for example:
    # python -m secure_transfer.client send-message --message "hello"
    parser = argparse.ArgumentParser(description="Secure transfer client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--base-dir", default=".")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_message = subparsers.add_parser("send-message", help="Sign and upload a text message")
    send_message.add_argument("--sender", default="student-client")
    send_message.add_argument("--name", default="message.txt")
    send_message.add_argument("--message", required=True)

    send_file = subparsers.add_parser("send-file", help="Sign and upload a file")
    send_file.add_argument("--sender", default="student-client")
    send_file.add_argument("--path", required=True)

    subparsers.add_parser("list", help="List encrypted records")

    download = subparsers.add_parser("download", help="Download and verify a stored record")
    download.add_argument("--record-id", required=True)
    download.add_argument("--out", required=True)

    verify = subparsers.add_parser("verify", help="Verify digest and signature for a stored record")
    verify.add_argument("--record-id", required=True)

    args = parser.parse_args()
    client = SecureTransferClient(args.host, args.port, Path(args.base_dir).resolve())

    # Choose which action to run based on the command typed by the user.
    if args.command == "send-message":
        _print_response(client.upload("message", args.name, args.sender, args.message.encode("utf-8")))
    elif args.command == "send-file":
        path = Path(args.path)
        _print_response(client.upload("file", path.name, args.sender, path.read_bytes()))
    elif args.command == "list":
        _print_response(client.request({"command": "list"}))
    elif args.command == "verify":
        _print_response(client.request({"command": "verify", "record_id": args.record_id}))
    elif args.command == "download":
        response = client.request({"command": "download", "record_id": args.record_id})
        if response.get("ok"):
            Path(args.out).write_bytes(base64.b64decode(response["data_b64"].encode("ascii")))
        _print_response(response)


if __name__ == "__main__":
    main()
