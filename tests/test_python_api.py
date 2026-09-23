import unittest

import tgcrypto
import tgcryptors


class TgCryptoApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = bytes(range(64))
        self.key = bytes(range(32))
        self.iv_ige = bytes(range(32))
        self.iv_cbc = bytes(range(16))

    def test_stateless_roundtrips(self) -> None:
        encrypted_ige = tgcrypto.ige256_encrypt(self.data, self.key, self.iv_ige)
        self.assertEqual(
            tgcrypto.ige256_decrypt(encrypted_ige, self.key, self.iv_ige),
            self.data,
        )

        encrypted_cbc = tgcrypto.cbc256_encrypt(self.data, self.key, self.iv_cbc)
        self.assertEqual(
            tgcrypto.cbc256_decrypt(encrypted_cbc, self.key, self.iv_cbc),
            self.data,
        )

        ctr_data = self.data + b"xyz"
        encrypted_ctr = tgcrypto.ctr256_encrypt(ctr_data, self.key, self.iv_cbc, b"\x00")
        self.assertEqual(
            tgcrypto.ctr256_decrypt(encrypted_ctr, self.key, self.iv_cbc, b"\x00"),
            ctr_data,
        )

    def test_ctr_stream_matches_one_shot(self) -> None:
        expected = tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x00")
        stream = tgcrypto.Ctr256(self.key, self.iv_cbc)

        actual = (
            stream.update(self.data[:17])
            + stream.update(self.data[17:41])
            + stream.update(self.data[41:])
        )

        self.assertEqual(actual, expected)

    def test_ctr_accepts_bytearray(self) -> None:
        expected = tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x00")

        ciphertext = tgcrypto.ctr256_encrypt(
            bytearray(self.data),
            bytearray(self.key),
            bytearray(self.iv_cbc),
            bytearray(1),
        )

        self.assertEqual(ciphertext, expected)

    def test_ctr_bytearray_state_carries_across_calls(self) -> None:
        data = self.data + b"payload" * 40
        expected = tgcrypto.ctr256_encrypt(data, self.key, self.iv_cbc, b"\x00")

        enc_iv = bytearray(self.iv_cbc)
        enc_state = bytearray(1)
        ciphertext = (
            tgcrypto.ctr256_encrypt(data[:100], self.key, enc_iv, enc_state)
            + tgcrypto.ctr256_encrypt(data[100:333], self.key, enc_iv, enc_state)
            + tgcrypto.ctr256_encrypt(data[333:], self.key, enc_iv, enc_state)
        )

        self.assertEqual(ciphertext, expected)

        dec_iv = bytearray(self.iv_cbc)
        dec_state = bytearray(1)
        plaintext = (
            tgcrypto.ctr256_decrypt(ciphertext[:5], self.key, dec_iv, dec_state)
            + tgcrypto.ctr256_decrypt(ciphertext[5:700], self.key, dec_iv, dec_state)
            + tgcrypto.ctr256_decrypt(ciphertext[700:], self.key, dec_iv, dec_state)
        )

        self.assertEqual(plaintext, data)

    def test_ctr_bytearray_large_chunked_roundtrip(self) -> None:
        data = bytes(range(256)) * 2048
        key = self.key
        iv0 = self.iv_cbc

        enc_iv = bytearray(iv0)
        enc_state = bytearray(1)
        ciphertext = b""
        for i in range(0, len(data), 65553):
            ciphertext += tgcrypto.ctr256_decrypt(
                data[i : i + 65553], key, enc_iv, enc_state
            )

        dec_iv = bytearray(iv0)
        dec_state = bytearray(1)
        plaintext = b""
        for i in range(0, len(ciphertext), 65553):
            plaintext += tgcrypto.ctr256_decrypt(
                ciphertext[i : i + 65553], key, dec_iv, dec_state
            )

        self.assertEqual(plaintext, data)

    def test_ctr_bytearray_mutates_iv_and_state_in_place(self) -> None:
        data = self.data + b"xyz"  # 67 bytes, not block aligned
        iv = bytearray(self.iv_cbc)
        state = bytearray(1)

        tgcrypto.ctr256_encrypt(data, self.key, iv, state)

        self.assertEqual(state[0], len(data) % 16)
        self.assertNotEqual(iv, bytearray(self.iv_cbc))

    def test_ctr_bytes_do_not_mutate_iv_or_state(self) -> None:
        data = self.data + b"xyz"  # 67 bytes, not block aligned
        iv = self.iv_cbc
        state = b"\x00"

        ciphertext1 = tgcrypto.ctr256_encrypt(data, self.key, iv, state)
        ciphertext2 = tgcrypto.ctr256_encrypt(data, self.key, iv, state)

        self.assertEqual(iv, self.iv_cbc)
        self.assertEqual(state, b"\x00")
        self.assertEqual(ciphertext1, ciphertext2)

    def test_ige_stream_matches_one_shot(self) -> None:
        expected = tgcrypto.ige256_encrypt(self.data, self.key, self.iv_ige)
        stream = tgcrypto.Ige256(self.key, self.iv_ige)

        actual = (
            stream.encrypt(self.data[:16])
            + stream.encrypt(self.data[16:32])
            + stream.encrypt(self.data[32:])
        )

        self.assertEqual(actual, expected)

        decrypt_stream = tgcrypto.Ige256(self.key, self.iv_ige)
        decrypted = (
            decrypt_stream.decrypt(expected[:16])
            + decrypt_stream.decrypt(expected[16:32])
            + decrypt_stream.decrypt(expected[32:])
        )
        self.assertEqual(decrypted, self.data)

    def test_empty_inputs_are_supported(self) -> None:
        self.assertEqual(tgcrypto.ige256_encrypt(b"", self.key, self.iv_ige), b"")
        self.assertEqual(tgcrypto.ige256_decrypt(b"", self.key, self.iv_ige), b"")
        self.assertEqual(tgcrypto.cbc256_encrypt(b"", self.key, self.iv_cbc), b"")
        self.assertEqual(tgcrypto.cbc256_decrypt(b"", self.key, self.iv_cbc), b"")
        self.assertEqual(tgcrypto.ctr256_encrypt(b"", self.key, self.iv_cbc, b"\x00"), b"")
        self.assertEqual(tgcrypto.ctr256_decrypt(b"", self.key, self.iv_cbc, b"\x00"), b"")

        self.assertEqual(tgcrypto.Ctr256(self.key, self.iv_cbc).update(b""), b"")
        self.assertEqual(tgcrypto.Ige256(self.key, self.iv_ige).encrypt(b""), b"")
        self.assertEqual(tgcrypto.Ige256(self.key, self.iv_ige).decrypt(b""), b"")

    def test_validation_errors_are_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "Key must be exactly 32 bytes"):
            tgcrypto.ctr256_encrypt(self.data, b"\x00" * 31, self.iv_cbc, b"\x00")

        with self.assertRaisesRegex(ValueError, "IV must be exactly 16 bytes"):
            tgcrypto.cbc256_encrypt(self.data, self.key, b"\x00" * 15)

        with self.assertRaisesRegex(ValueError, "multiple of 16 bytes"):
            tgcrypto.ige256_encrypt(self.data[:-1], self.key, self.iv_ige)

        with self.assertRaisesRegex(ValueError, "State value must be in the range \\[0, 15\\]"):
            tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, b"\x10")

    def test_ctr_bytearray_validation_errors_are_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "Key must be exactly 32 bytes"):
            tgcrypto.ctr256_encrypt(self.data, bytearray(31), self.iv_cbc, b"\x00")

        with self.assertRaisesRegex(ValueError, "IV must be exactly 16 bytes"):
            tgcrypto.ctr256_encrypt(self.data, self.key, bytearray(15), b"\x00")

        with self.assertRaisesRegex(ValueError, "State value must be in the range \\[0, 15\\]"):
            tgcrypto.ctr256_encrypt(self.data, self.key, self.iv_cbc, bytearray(b"\x10"))

        with self.assertRaises(TypeError):
            tgcrypto.ctr256_encrypt(self.data, "not bytes", self.iv_cbc, b"\x00")

        with self.assertRaises(TypeError):
            tgcrypto.ctr256_encrypt(self.data, self.key, "not bytes", b"\x00")

    def test_docstrings_are_available(self) -> None:
        self.assertIn("Encrypt bytes with AES-256-CTR", tgcrypto.ctr256_encrypt.__doc__)
        self.assertIn("Stateful AES-256-CTR stream cipher", tgcrypto.Ctr256.__doc__)
        self.assertIn("Encrypt or decrypt the next chunk", tgcrypto.Ctr256.update.__doc__)
        self.assertIn("Stateful AES-256-IGE stream cipher", tgcrypto.Ige256.__doc__)

    def test_runtime_metadata_is_available(self) -> None:
        self.assertEqual(tgcrypto.__version__, "1.3.2")

        info = tgcrypto.runtime_info()

        self.assertEqual(info["version"], tgcrypto.__version__)
        self.assertEqual(info["crate_version"], tgcrypto.__version__)
        self.assertEqual(info["implementation"], "rust")
        self.assertIsInstance(info["aesni"], bool)
        self.assertIsInstance(info["aesni_compiled"], bool)

    def test_nist_sp800_38a_ctr_cbc_known_answers(self) -> None:
        key = bytes.fromhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a20914dff4"
        )
        plaintext = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45f11162"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        # NIST SP 800-38A F.5.5 CTR-AES256.Encrypt
        ctr_iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        ctr_expected = bytes.fromhex(
            "2e6274c24ed1e2f3206fcf48162d2042"
            "c8f450e4c9229675fb2f162f036432d0"
            "9abf7567a68b9a223295eea7b60b5314"
            "c7ad58ae08f2ba14743d1d136e47a0e9"
        )
        self.assertEqual(
            tgcrypto.ctr256_encrypt(plaintext, key, ctr_iv, b"\x00"),
            ctr_expected,
        )
        self.assertEqual(
            tgcrypto.ctr256_decrypt(ctr_expected, key, ctr_iv, b"\x00"),
            plaintext,
        )

        # NIST SP 800-38A F.5.3 CBC-AES256.Encrypt
        cbc_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        cbc_expected = bytes.fromhex(
            "a58c38079fab0b976fd94e6ff61fc943"
            "d46513dda7b29de14bd3b878a77240a4"
            "d4994bb56bf379d9f74a36a8210f3ba1"
            "dcd6ae01dd1949e7a02bd1010a8081b9"
        )
        self.assertEqual(
            tgcrypto.cbc256_encrypt(plaintext, key, cbc_iv),
            cbc_expected,
        )
        self.assertEqual(
            tgcrypto.cbc256_decrypt(cbc_expected, key, cbc_iv),
            plaintext,
        )

    def test_ige256_known_answer(self) -> None:
        # Vector generated independently from the spec (ECB primitive via the
        # `cryptography` library + IGE chaining equations).
        key = bytes(range(32))
        iv = bytes(range(32))
        plaintext = bytes(range(64))
        expected = bytes.fromhex(
            "e28112a53e5c89c7b1ea8071c133699f"
            "d4e86b26c4bac9fc5af1ab8ce27a44a4"
            "a9b2dabae5a422acbb4422404b5950cc"
            "e880d70cef7a432da00b3a5fc79a7b35"
        )
        self.assertEqual(tgcrypto.ige256_encrypt(plaintext, key, iv), expected)
        self.assertEqual(tgcrypto.ige256_decrypt(expected, key, iv), plaintext)

    def test_tgcrypto_and_tgcryptors_imports_match(self) -> None:
        self.assertEqual(tgcrypto.__version__, tgcryptors.__version__)
        self.assertIs(tgcrypto.Ctr256, tgcryptors.Ctr256)
        self.assertIs(tgcrypto.Ige256, tgcryptors.Ige256)

        encrypted = tgcryptors.ctr256_encrypt(
            self.data,
            self.key,
            self.iv_cbc,
            b"\x00",
        )
        decrypted = tgcrypto.ctr256_decrypt(
            encrypted,
            self.key,
            self.iv_cbc,
            b"\x00",
        )

        self.assertEqual(decrypted, self.data)


if __name__ == "__main__":
    unittest.main()
