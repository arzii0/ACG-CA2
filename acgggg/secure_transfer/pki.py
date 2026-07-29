"""Generate encrypted RSA keys and CA-signed certificates for the demo PKI."""

# Task allocation - Xavier (Chung Yi Jun Xavier):
# Implemented the PKI and key-management component, including RSA-3072 key
# generation, password-encrypted PEM private keys, CA certificate signing,
# certificate extensions and certificate key-usage restrictions.

from __future__ import annotations

import argparse
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _new_key() -> rsa.RSAPrivateKey:
    """Create one RSA-3072 private key."""

    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _required_password(variable_name: str) -> str:
    """Read a required private-key password from an environment variable."""

    password = os.getenv(variable_name)
    if not password:
        raise RuntimeError(
            f"{variable_name} is not set. Set it before generating the PKI."
        )
    return password


def _write_key(path: Path, key: rsa.RSAPrivateKey, password: str) -> None:
    """Save a private key as an encrypted PEM file."""

    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    """Save a public certificate as a PEM file."""

    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _name(common_name: str) -> x509.Name:
    """Create a certificate subject or issuer name."""

    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SP ST2504 Assignment 2"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _make_signed_cert(
    subject_name: x509.Name,
    subject_key: rsa.RSAPrivateKey,
    issuer_name: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    is_ca: bool,
    eku: ExtendedKeyUsageOID | None = None,
) -> x509.Certificate:
    """Create and sign one X.509 certificate."""

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
    )

    # Key Usage explicitly controls how the certificate's public key may be used.
    if is_ca:
        # The CA may sign client and server certificates.
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        # Client/server identities may authenticate, sign, and establish TLS sessions.
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Link the client/server certificate to the CA that signed it.
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )

    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([eku]),
            critical=False,
        )

    # The server runs locally for this assignment demo.
    if subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "localhost":
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )

    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def generate_pki(out_dir: Path) -> None:
    """Generate a CA, client, and server identity with encrypted private keys."""

    # Passwords are provided at runtime and are not stored in source code.
    ca_password = _required_password("ACG_CA_KEY_PASSWORD")
    server_password = _required_password("ACG_SERVER_KEY_PASSWORD")
    client_password = _required_password("ACG_CLIENT_KEY_PASSWORD")

    out_dir.mkdir(parents=True, exist_ok=True)

    # Certificate Authority signs the server and client certificates.
    ca_key = _new_key()
    ca_name = _name("Aetheria Demo CA")
    ca_cert = _make_signed_cert(ca_name, ca_key, ca_name, ca_key, True)

    # Server identity for TLS.
    server_key = _new_key()
    server_cert = _make_signed_cert(
        _name("localhost"),
        server_key,
        ca_cert.subject,
        ca_key,
        False,
        ExtendedKeyUsageOID.SERVER_AUTH,
    )

    # Client identity for mutual TLS and digital signatures.
    client_key = _new_key()
    client_cert = _make_signed_cert(
        _name("student-client"),
        client_key,
        ca_cert.subject,
        ca_key,
        False,
        ExtendedKeyUsageOID.CLIENT_AUTH,
    )

    _write_key(out_dir / "ca.key", ca_key, ca_password)
    _write_cert(out_dir / "ca.crt", ca_cert)

    _write_key(out_dir / "server.key", server_key, server_password)
    _write_cert(out_dir / "server.crt", server_cert)

    _write_key(out_dir / "client.key", client_key, client_password)
    _write_cert(out_dir / "client.crt", client_cert)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate encrypted RSA keys and certificates for the demo PKI."
    )
    parser.add_argument(
        "--out",
        default="deployment/pki",
        help="Output folder for keys and certificates.",
    )
    args = parser.parse_args()

    generate_pki(Path(args.out))
    print(f"Generated encrypted CA, server, and client keys in {args.out}")


if __name__ == "__main__":
    main()
