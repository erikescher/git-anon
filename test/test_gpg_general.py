import datetime
from typing import Tuple, List
from unittest import TestCase

import pgpy
from pgpy import PGPUID, PGPKey, PGPSignature

from git_anon.gpg_general import get_pseudo_uid, uid_is_in, contains_userid, may_certify, may_certify_any, add_uid, \
    create_identity
from git_anon.gpg_general import get_uniform_time_as_datetime
from git_anon.gpg_general import parse_uid
from git_anon.gpg_general import uid_as_str
from git_anon.gpg_general import uid_equals


class Test(TestCase):

    def test_get_uniform_time_as_datetime(self):
        time = get_uniform_time_as_datetime()
        # the presence of timezone info seems to break some stuff and could reveal information about the user
        self.assertIsNone(time.tzinfo)
        # timestamp is documented to equal 2001-09-09T01:46:40+00:00
        self.assertEqual(time.year, 2001)
        self.assertEqual(time.month, 9)
        self.assertEqual(time.day, 9)
        self.assertEqual(time.hour, 1)
        self.assertEqual(time.minute, 46)
        self.assertEqual(time.second, 40)
        # unix timestamps do not have microsecond resolution
        self.assertEqual(time.microsecond, 0)
        # ensure that it matches the expected timestamp
        self.assertEqual(time, datetime.datetime.utcfromtimestamp(1000000000))

    def test_uid_as_str(self):
        self.assertEqual(uid_as_str(PGPUID.new("First Middle b. Last", "Some Comment", "email@example.org")),
                         "First Middle b. Last (Some Comment) <email@example.org>")
        self.assertEqual(uid_as_str(PGPUID.new("Just a Name")), "Just a Name")

        # noinspection PyTypeChecker
        self.assertRaises(TypeError, lambda: uid_as_str(None))

    def test_get_pseudo_uid(self):
        pseudo_uid = get_pseudo_uid()
        self.assertEqual(pseudo_uid.name, "Git-Anon User")
        self.assertEqual(pseudo_uid.email, "")
        self.assertEqual(pseudo_uid.comment, "")
        self._check_uid_valid(pseudo_uid)
        self.assertEqual(pseudo_uid.hashdata, b"Git-Anon User")

    def test_uid_equals(self):
        self.assertTrue(uid_equals(PGPUID.new("a", "b", "c"), PGPUID.new("a", "b", "c")))
        self.assertFalse(uid_equals(PGPUID.new("a", "b", "c"), PGPUID.new("A", "b", "c")))
        self.assertFalse(uid_equals(PGPUID.new("a", "b", "c"), PGPUID.new("a", "B", "c")))
        self.assertFalse(uid_equals(PGPUID.new("a", "b", "c"), PGPUID.new("a", "b", "C")))
        self.assertFalse(uid_equals(PGPUID.new("a", "b", "c"), PGPUID.new("a", "b")))
        uid = PGPUID.new("a")
        self.assertTrue(uid_equals(uid, uid))

    def test_parse_uid(self):
        uid = parse_uid("First Middle b. Last (Some Comment) <email@example.org>")
        self.assertEqual(uid.name, "First Middle b. Last")
        self.assertEqual(uid.comment, "Some Comment")
        self.assertEqual(uid.email, "email@example.org")
        self._check_uid_valid(uid)

        self.assertIsNone(parse_uid(""))

    def test_uid_is_in(self):
        uid = "John Doe"
        desired_uids = [
            "Mister Example",
            uid,
            PGPUID.new("Jane Doe")
        ]
        self.assertTrue(uid_is_in(uid, desired_uids))
        self.assertTrue(uid_is_in(PGPUID.new(uid), desired_uids))
        self.assertTrue(uid_is_in("Jane Doe", desired_uids))
        self.assertFalse(uid_is_in("Not in there", desired_uids))
        self.assertFalse(uid_is_in(uid, None))
        self.assertFalse(uid_is_in(uid, []))

    def _check_uid_valid(self, uid: PGPUID) -> None:
        self.assertIsNone(uid.selfsig)
        self.assertEqual(len(uid.__sig__), 0)
        self.assertEqual(uid.is_uid, True)
        self.assertEqual(uid.is_ua, False)
        # self.assertEqual(pseudo_uid.is_primary, False) # there is no self-signature and this throws an error

    def test_create_identity(self):
        _, secondary_uids = self._create_test_key()
        primary_uid = PGPUID.new("Primary")

        pub, sec = create_identity(primary_uid, secondary_uids)

        self.assertEqual(pub.fingerprint, sec.fingerprint)

        self.assertTrue(pub.is_public)
        self.assertFalse(sec.is_public)
        self.assertFalse(sec.is_protected)

        self.assertEqual(pub.created, get_uniform_time_as_datetime())
        self.assertEqual(pub.key_algorithm, pgpy.constants.PubKeyAlgorithm.EdDSA)
        self.assertEqual(pub.key_size, pgpy.constants.EllipticCurveOID.Ed25519)

        self.assertIsNotNone(pub.get_uid(get_pseudo_uid().name))
        primary_uid_from_key: PGPUID = pub.get_uid("Primary")
        self.assertIsNotNone(primary_uid_from_key)
        self.assertTrue(primary_uid_from_key.is_primary)
        self.assertEqual(len(pub.userids), 6)
        primary_uid_count = 0
        for u in pub.userids:
            self.assertIsNotNone(u.selfsig)
            self.assertEqual(u.selfsig.created, get_uniform_time_as_datetime())
            if u.is_primary:
                primary_uid_count += 1
        self.assertEqual(primary_uid_count, 1)

    def test_add_uid(self):
        key = PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        add_uid(key, PGPUID.new("Name"), primary=True)

        self.assertEqual(len(key.userids), 1)
        self.assertIsNotNone(key.get_uid("Name"))
        self.assertTrue(key.get_uid("Name").is_primary)

        new_uid: PGPUID = key.get_uid("Name")
        self.assertIsNotNone(new_uid.selfsig)
        self.assertEqual(new_uid.signers.pop(), key.fingerprint.keyid)
        self.assertTrue(key.verify(new_uid))
        uid_sig: PGPSignature = new_uid.selfsig
        self.assertEqual(uid_sig.created, get_uniform_time_as_datetime())
        self.assertListEqual(uid_sig.cipherprefs, [pgpy.constants.SymmetricKeyAlgorithm.AES256])
        self.assertListEqual(uid_sig.compprefs, [pgpy.constants.CompressionAlgorithm.Uncompressed])
        self.assertListEqual(uid_sig.hashprefs, [pgpy.constants.HashAlgorithm.SHA512])


        add_uid(key, PGPUID.new("Secondary"), False)
        self.assertEqual(len(key.userids), 2)
        self.assertFalse(key.get_uid("Secondary").is_primary)

    @staticmethod
    def _create_test_key() -> Tuple[PGPKey, List[PGPUID]]:
        userids: List[PGPUID] = [PGPUID.new("UID 1"), PGPUID.new("UID 2"), PGPUID.new("UID 3"), PGPUID.new("UID 4")]
        key = PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 512)
        for userid in userids:
            key.add_uid(userid, selfsign=True)
        return key, userids

    def test_may_certify(self):
        key, userids = self._create_test_key()

        self.assertTrue(may_certify(userids[2], key))
        self.assertTrue(may_certify(PGPUID.new("UID 4"), key))
        self.assertTrue(may_certify("UID 4", key))
        self.assertFalse(may_certify(PGPUID.new("Not present"), key))
        self.assertFalse(may_certify("Not present", key))

    def test_may_certify_any(self):
        key, userids = self._create_test_key()

        self.assertTrue(may_certify_any([userids[2], "Not present"], key))
        self.assertTrue(may_certify_any(["Not present", userids[2]], key))
        self.assertTrue(may_certify_any(["1", "2", "3", PGPUID.new("UID 4")], key))
        self.assertFalse(may_certify_any([PGPUID.new("Not present")], key))
        self.assertFalse(may_certify_any(["1", "2", "3"], key))
        self.assertFalse(may_certify_any([], key))

    def test_contains_userid(self):
        key, userids = self._create_test_key()

        self.assertTrue(contains_userid(key, userids[2]))
        self.assertTrue(contains_userid(key, PGPUID.new("UID 4")))
        self.assertTrue(contains_userid(key, "UID 4"))
        self.assertFalse(contains_userid(key, PGPUID.new("Not present")))
        self.assertFalse(contains_userid(key, "Not present"))

