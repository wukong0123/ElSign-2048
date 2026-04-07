import unittest

from main import (
    decrypt_alpha_message,
    decrypt_bytes,
    encrypt_alpha_message,
    encrypt_bytes,
    generate_keypair,
    normalize_alpha_message,
    sign_bytes,
    verify_signature,
)


class ElGamalTests(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self) -> None:
        public_key, private_key = generate_keypair()
        message = ("ElGamal 2048-bit " * 20).encode("utf-8")
        ciphertext = encrypt_bytes(message, public_key)
        plaintext = decrypt_bytes(ciphertext, private_key)
        self.assertEqual(plaintext, message)

    def test_sign_verify_roundtrip(self) -> None:
        public_key, private_key = generate_keypair()
        message = b"Chu ky so ElGamal"
        signature = sign_bytes(message, private_key)
        self.assertTrue(verify_signature(message, signature, public_key))
        self.assertFalse(verify_signature(message + b"!", signature, public_key))

    def test_alpha_message_normalization(self) -> None:
        self.assertEqual(normalize_alpha_message("Xin chao 2026!"), "XINCHAO")

    def test_alpha_encrypt_decrypt_roundtrip(self) -> None:
        public_key, private_key = generate_keypair()
        ciphertext = encrypt_alpha_message("aAz zoo", public_key)
        plaintext = decrypt_alpha_message(ciphertext, private_key)
        self.assertEqual(plaintext, "AAZZOO")


if __name__ == "__main__":
    unittest.main()
