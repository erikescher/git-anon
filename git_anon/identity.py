import re
from typing import Optional, Tuple

# anonymous identity would be the identity added to author and committer fields
import pgpy
from pgpy import PGPUID

from git_anon.custom_exception import CustomException
from git_anon.gpg_general import may_certify
from git_anon.keystores.gpg_keystore_trusted import TrustedKeyStore


def verify_uid(uid: PGPUID, trusted_keystore: TrustedKeyStore) -> bool:
    for signer in uid.signers:
        if signer == uid.selfsig.signer:
            # This is a self-signature that has been checked previously.
            continue
        certification_key = trusted_keystore.get_key(signer)
        if certification_key is None:
            # the signer is not trusted to certify anything
            continue
        if not may_certify(uid, certification_key):
            # the signer is not trusted to certify this uid (only others)
            continue
        if certification_key.verify(uid):
            # we have at least one valid certification
            return True
    return False


def extract_keyid_from_identity(identity: str) -> Tuple[str, Optional[pgpy.pgp.Fingerprint]]:
    regex = "^(ANON )?(?P<keyid>[1234567890abcdefABCDEF]+) ?.*$"
    match = re.match(regex, identity)
    if match is None:
        raise CustomException("Not a git-anon identity. Format does not match.")
    keyid: str = match.groupdict()["keyid"]
    keyid_len = len(keyid)
    if keyid_len not in (16, 40):
        # keyid is invalid
        raise CustomException("Not a git-anon identity. Invalid length: ", keyid_len)

    if keyid_len == 40:
        return keyid[-16:], pgpy.pgp.Fingerprint(keyid)
    return keyid[-16:], None


def identity_from_keyid(keyid: str) -> Tuple[str, str]:
    identity_name = "ANON " + keyid
    identity_mail = keyid + "@" + "git-anon"

    return identity_name, identity_mail
