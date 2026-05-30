"""Tests for AES-GCM encryption in profile storage."""
import unittest
import base64
import hashlib
import hmac
import json
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
        from browser.core.storage import BrowserStorage, StorageError
        key = hashlib.pbkdf2_hmac("sha256", b"password", b"testsalt", 210000, dklen=32)
        storage = BrowserStorage.__new__(BrowserStorage)
        encrypted = storage._encrypt_json({"hello": "world"}, key)
        self.assertTrue(encrypted.startswith("enc:v2:"))
        decrypted = storage._decrypt_json(encrypted, key)
        self.assertEqual(decrypted, {"hello": "world"})

    def test_encrypt_json_wrong_key_fails(self):
        from browser.core.storage import BrowserStorage, StorageError
        key1 = hashlib.pbkdf2_hmac("sha256", b"pass1", b"saltx", 210000, dklen=32)
        key2 = hashlib.pbkdf2_hmac("sha256", b"pass2", b"saltx", 210000, dklen=32)
        storage = BrowserStorage.__new__(BrowserStorage)
        encrypted = storage._encrypt_json("secret", key1)
        with self.assertRaises(Exception):
            storage._decrypt_json(encrypted, key2)


if __name__ == "__main__":
    unittest.main()
