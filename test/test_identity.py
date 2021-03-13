from unittest import TestCase

from pgpy.types import Fingerprint

from git_anon.custom_exception import CustomException
from git_anon.identity import extract_keyid_from_identity, identity_from_keyid


class Test(TestCase):
    def test_extract_keyid_from_identity(self):
        identity = "ANON 12345678ABCDef00"
        keyid, fingerprint = extract_keyid_from_identity(identity)
        self.assertEqual(keyid, "12345678ABCDef00")
        self.assertEqual(type(keyid), str)
        self.assertIsNone(fingerprint)

        self.assertEqual(extract_keyid_from_identity("1234567890abcdef")[0], "1234567890abcdef")

        fingerprint = "1234567890123456789012345678901234567890"
        self.assertEqual(extract_keyid_from_identity("ANON " + fingerprint),
                         (fingerprint[-16:], Fingerprint(fingerprint)))

        self.assertRaises(CustomException, lambda: extract_keyid_from_identity("John Doe"))
        self.assertRaises(CustomException, lambda: extract_keyid_from_identity("ANON 123456789"))
        self.assertRaises(CustomException, lambda: extract_keyid_from_identity("ANON 123456ab"))
        self.assertRaises(CustomException, lambda: extract_keyid_from_identity("ANON 123456ab <some-mail@example.com>"))

    def test_identity_from_keyid(self):
        self.assertTupleEqual(identity_from_keyid("MY_KEY_ID"), ("ANON MY_KEY_ID", "MY_KEY_ID@git-anon"))
