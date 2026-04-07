import unittest

from main import decrypt_bytes, encrypt_bytes, generate_keypair, sign_bytes, verify_signature


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


if __name__ == "__main__":
    unittest.main()
