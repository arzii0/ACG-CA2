"""Tests for strong password generation and private-key re-encryption."""

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from secure_transfer.password_manager import (
    change_private_key_password,
    generate_strong_password,
)


class PasswordManagerTests(unittest.TestCase):
    def test_generated_passwords_are_strong_and_different(self) -> None:
        first = generate_strong_password()
        second = generate_strong_password()

        self.assertGreaterEqual(len(first), 32)
        self.assertNotEqual(first, second)

    def test_private_key_can_be_reencrypted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "client.key"
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            key_path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        b"old-password"
                    ),
                )
            )

            new_password = change_private_key_password(
                key_path,
                "old-password",
            )

            loaded_key = serialization.load_pem_private_key(
                key_path.read_bytes(),
                password=new_password.encode("utf-8"),
            )

            self.assertEqual(
                loaded_key.public_key().public_numbers(),
                key.public_key().public_numbers(),
            )


if __name__ == "__main__":
    unittest.main()