import datetime
import re
from typing import Tuple, Optional, Union, List

import pgpy
from pgpy import PGPKey, PGPUID
from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm, CompressionAlgorithm

from git_anon.library_patches.patched_pgpy_functions import patched_pgpy_add_uid

PGPUID_or_str = Union[PGPUID, str]


def create_identity(primary_uid: Optional[PGPUID], secondary_uids: List[PGPUID]) -> Tuple[PGPKey, PGPKey]:
    # Ed25519 (signature variant of Curve25519) was chosen for its small size and presumably lower demand for entropy.
    # The system will be generating lots of keys so both will be important.
    key = pgpy.PGPKey.new(
        pgpy.constants.PubKeyAlgorithm.EdDSA,
        pgpy.constants.EllipticCurveOID.Ed25519,
        get_uniform_time_as_datetime()
    )

    add_uid(key, get_pseudo_uid())
    if primary_uid is not None:
        add_uid(key, primary_uid, primary=True)
    for uid in secondary_uids:
        add_uid(key, uid)
        # sign the new uid with appropriate keys?
    return key.pubkey, key


def get_uniform_time_as_datetime() -> datetime.datetime:
    # a timestamp of 1000000000 causes different treatment in gpg
    # (in particular printing of "aka" lines for secondary userids)
    # this corresponds to a date of 2001-09-09T01:46:40+00:00 and was chosen for its "round" timestamp value
    return datetime.datetime.fromtimestamp(1000000000, tz=datetime.timezone.utc).replace(tzinfo=None)


def add_uid(key: PGPKey, uid: PGPUID, primary: bool = False) -> None:
    patched_pgpy_add_uid(
        key,
        uid,
        selfsign=True,
        ciphers=[SymmetricKeyAlgorithm.AES256],
        hashes=[HashAlgorithm.SHA512],
        compression=[CompressionAlgorithm.Uncompressed],
        primary=primary,
        created=get_uniform_time_as_datetime()
    )


def uid_as_str(uid: PGPUID_or_str) -> str:
    if isinstance(uid, PGPUID):
        return uid.__format__("unused")
    if isinstance(uid, str):
        return uid
    raise TypeError("Expecting pgpy.pgp.PGPUID or str but got" + str(type(uid)))


def may_certify(target_userid: PGPUID_or_str, signature_key: PGPKey) -> bool:
    # Currently this just means that the signature key has a user id that matches the user id to be certified.
    return contains_userid(signature_key, target_userid)


def may_certify_any(target_userids: List[PGPUID_or_str], signature_key: PGPKey) -> bool:
    for target_userid in target_userids:
        if may_certify(target_userid, signature_key):
            return True
    return False


def contains_userid(key: PGPKey, userid: PGPUID_or_str) -> bool:
    for userid_on_key in key.userids:
        if uid_equals(userid_on_key, userid):
            return True
    return False


def get_pseudo_uid() -> PGPUID:
    return PGPUID.new("Git-Anon User")


def uid_equals(uid1: PGPUID_or_str, uid2: PGPUID_or_str) -> bool:
    return uid_as_str(uid1) == uid_as_str(uid2)
    # should I compare based on the attributes or hash data instead?


def uid_is_in(actual_uid: PGPUID_or_str, desired_uids: List[PGPUID_or_str]) -> bool:
    if desired_uids is not None:
        for desired_uid in desired_uids:
            if uid_equals(actual_uid, desired_uid):
                return True
    return False


def parse_uid(uid: str) -> Optional[pgpy.PGPUID]:
    uid_regex = r"^(?P<name>.+?)( \((?P<comment>.+?)\)(?=( <|$)))?( <(?P<email>.+)>)?$"  # from pgpy.pgp.UserID:parse
    match = re.match(uid_regex, uid)
    if match is None:
        # alternatively raise an error because there was an invalid line in the configuration file
        return None
    regex_result = match.groupdict()
    return pgpy.PGPUID.new(regex_result['name'], regex_result['comment'] or "", regex_result['email'] or "")
