"""Tests for encrypted browser profile crypto helpers."""
import unittest
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TestCrypto(unittest.TestCase):
    def test_aes_gcm_roundtrip(self):
        key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 210000, dklen=32)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        plaintext = b"hello world"
        ct = aesgcm.encrypt(nonce, plaintext, None)
        pt = aesgcm.decrypt(nonce, ct, None)
        self.assertEqual(pt, plaintext)

    def test_aes_gcm_tampered_detected(self):
        key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 210000, dklen=32)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, b"hello world", None)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(Exception):
            aesgcm.decrypt(nonce, bytes(tampered), None)

    def test_encrypt_decrypt_json_v2(self):
        from browser.core.profile_crypto import decrypt_json, derive_password_key, encrypt_json
        key = derive_password_key("password", "0123456789abcdeffedcba9876543210")
        encrypted = encrypt_json({"hello": "world"}, key)
        self.assertTrue(encrypted.startswith("enc:v2:"))
        decrypted = decrypt_json(encrypted, key)
        self.assertEqual(decrypted, {"hello": "world"})

    def test_encrypt_json_wrong_key_fails(self):
        from browser.core.profile_crypto import ProfileCryptoError, decrypt_json, derive_password_key, encrypt_json
        salt_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        key1 = derive_password_key("pass1", salt_hex)
        key2 = derive_password_key("pass2", salt_hex)
        encrypted = encrypt_json("secret", key1)
        with self.assertRaises(ProfileCryptoError):
            decrypt_json(encrypted, key2)


if __name__ == "__main__":
    unittest.main()
