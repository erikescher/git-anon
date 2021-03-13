from unittest import TestCase

from git_anon.keystores.gpg_keystore_shared import SharedKeyStore, KeyDerivationHelper


class TestPGPPublicRepositoryKeyStore(TestCase):
    def test__hash_encryption_key(self):
        hash_value = KeyDerivationHelper.hash_encryption_key("123")
        self.assertEqual(hash_value, "4b219de1ab3e0fe2db91f27486b186023fad04d0f2ffc6ac245a3e7909fcbf8c")
        # equivalent to: echo -n "123git-anon-encryption-key-validation" | sha512sum
        self.assertEqual(type(hash_value), str)

    def test__derive_key(self):
        derived_key = KeyDerivationHelper._derive_key("my_salt", 2, 1, 3, "my_password")
        self.assertEqual(derived_key, "55c354afb067b5c4f94dd0c9e8f86d95c0658ca87a5771b014ffeb8273c65338")
        # equivalent to: https://www.browserling.com/tools/scrypt with identical parameters
        self.assertEqual(len(derived_key), 64)
