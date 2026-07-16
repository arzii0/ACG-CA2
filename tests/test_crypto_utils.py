"""Focused tests for Rui Zhong's AES-GCM and SHA-256 contribution."""

import unittest

from cryptography.exceptions import InvalidTag

from secure_transfer.crypto_utils import (
    calculate_sha256,
    decrypt_with_aes_gcm,
    encrypt_with_aes_gcm,
    generate_aes_key,
)


class TestAesGcmAndSha256(unittest.TestCase):
    def setUp(self) -> None:
        self.plaintext = bytes(range(256)) + b"ST2504 Applied Cryptography"
        self.aes_key = generate_aes_key()
        self.ciphertext, self.nonce = encrypt_with_aes_gcm(
            self.plaintext, self.aes_key
        )

    def test_decryption_restores_original_bytes(self) -> None:
        decrypted = decrypt_with_aes_gcm(
            self.ciphertext, self.aes_key, self.nonce
        )
        self.assertEqual(decrypted, self.plaintext)

    def test_hashes_match_after_successful_decryption(self) -> None:
        decrypted = decrypt_with_aes_gcm(
            self.ciphertext, self.aes_key, self.nonce
        )
        self.assertEqual(
            calculate_sha256(decrypted), calculate_sha256(self.plaintext)
        )

    def test_sha256_matches_known_test_vector(self) -> None:
        expected_hex = (
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(calculate_sha256(b"abc").hex(), expected_hex)

    def test_modified_ciphertext_is_rejected(self) -> None:
        modified = bytearray(self.ciphertext)
        modified[0] ^= 1

        with self.assertRaises(InvalidTag):
            decrypt_with_aes_gcm(bytes(modified), self.aes_key, self.nonce)

    def test_incorrect_key_is_rejected(self) -> None:
        with self.assertRaises(InvalidTag):
            decrypt_with_aes_gcm(
                self.ciphertext, generate_aes_key(), self.nonce
            )

    def test_incorrect_nonce_is_rejected(self) -> None:
        incorrect_nonce = bytes([self.nonce[0] ^ 1]) + self.nonce[1:]

        with self.assertRaises(InvalidTag):
            decrypt_with_aes_gcm(
                self.ciphertext, self.aes_key, incorrect_nonce
            )

    def test_key_and_nonce_have_expected_sizes(self) -> None:
        self.assertEqual(len(self.aes_key), 32)
        self.assertEqual(len(self.nonce), 12)

    def test_ciphertext_contains_authentication_tag(self) -> None:
        self.assertEqual(len(self.ciphertext), len(self.plaintext) + 16)

    def test_repeated_encryption_uses_fresh_nonce(self) -> None:
        _, second_nonce = encrypt_with_aes_gcm(self.plaintext, self.aes_key)
        self.assertNotEqual(second_nonce, self.nonce)

    def test_empty_bytes_can_be_encrypted(self) -> None:
        ciphertext, nonce = encrypt_with_aes_gcm(b"", self.aes_key)
        self.assertEqual(
            decrypt_with_aes_gcm(ciphertext, self.aes_key, nonce), b""
        )


if __name__ == "__main__":
    unittest.main()
