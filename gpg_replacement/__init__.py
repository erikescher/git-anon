#!/usr/bin/python3

"""Replacement for GnuPG for the purposes of Git-Anon.

A small script that replaces gpg for the purposes of git and uses the keystores maintained by git-anon to locate keys
for signing and verification.

The reason for this package is that gpg scales rather poorly with the number of keys in a keyring.
It takes multiple minutes to import a key into a keyring that already contains a few thousand keys, which is a regular
occurrence with git-anon.
This package instead uses the more efficient storage format of git-anon directly obviating the need to export keyring
that is compatible to gpg.
"""

import sys
from datetime import datetime
from typing import Tuple, List

from pgpy import PGPSignature, PGPKey, PGPUID

from git_anon.api_functions import APIInterface
from git_anon.gpg_general import uid_as_str, uid_equals
from git_anon.identity import verify_uid
from git_anon.library_patches.patched_pgpy_functions import patched_pgpy_sign

API = APIInterface(".")
args = sys.argv[1:]


def main():
    sys.stderr.write("in main")
    if args[1] == "-bsau":
        sign()
    else:
        verify()


def sign() -> None:
    # signature creation requested
    if len(args) != 3:
        raise Exception("Unexpected number of parameters encountered: {}".format(len(args)))
    if not args[0] == "--status-fd=2":
        raise Exception("Unexpected parameter encountered in args[0]: {}".format(args[0]))

    keyid = args[2]
    commit_data = sys.stdin.read()

    public_key = API.personal_keystore.get_key(keyid)
    if public_key is None:
        raise Exception("Public key with ID {} could not be found!".format(keyid))

    key = API.personal_keystore.get_private_key(public_key.fingerprint)
    if key is None:
        raise Exception("Private key with ID {} could not be found!".format(keyid))

    # using the key material directly bypasses checks on the key flags
    signature: PGPSignature = patched_pgpy_sign(key, commit_data)

    sys.stdout.write(str(signature))

    fingerprint = key.fingerprint.replace(" ", "")
    timestamp = int(signature.created.timestamp())
    hash_algo_id = signature.hash_algorithm
    unknown_2 = 2
    sig_type = "D"  # detached
    sig_pk_algo = signature.key_algorithm
    sig_class = "00"  # 2 hex digits with the OpenPGP signature class

    sys.stderr.writelines([
        "[GNUPG:] KEY_CONSIDERED {} {}\n".format(
            fingerprint, unknown_2
        ),
        "[GNUPG:] BEGIN_SIGNING H{}\n".format(
            hash_algo_id
        ),
        "[GNUPG:] SIG_CREATED {} {} {} {} {} {}\n".format(
            sig_type, sig_pk_algo, hash_algo_id, sig_class, timestamp, fingerprint
        )
    ])


def verify() -> None:
    # signature verification requested
    commit_data = sys.stdin.read()
    if len(args) != 5:
        raise Exception("Unexpected number of parameters encountered: {}".format(len(args)))
    if not args[0] == "--keyid-format=long":
        raise Exception("Unexpected parameter encountered in args[0]: {}".format(args[0]))
    if not args[1] == "--status-fd=1":
        raise Exception("Unexpected parameter encountered in args[1]: {}".format(args[1]))
    if not args[2] == "--verify":
        raise Exception("Unexpected parameter encountered in args[2]: {}".format(args[2]))
    filename = args[3]
    if not args[4] == "-":
        raise Exception("Unexpected parameter encountered in args[4]: {}".format(args[2]))

    signature = PGPSignature.from_file(filename)

    key = API.combined_keystore.get_key(signature.signer)
    if key is not None:
        if key.verify(commit_data, signature):
            trusted_uids, untrusted_uids = deduplicate_uids(verify_uid_certifications(key))

            status_to_user(signature, key, trusted_uids, untrusted_uids)
            status_to_caller(signature, key, trusted_uids)
        else:
            raise Exception("Invalid signature")
    else:
        raise NotImplementedError("Key not found")


def verify_uid_certifications(key: PGPKey) -> Tuple[List[PGPUID], List[PGPUID]]:
    trusted_uids: List[PGPUID] = []
    untrusted_uids: List[PGPUID] = []

    # todo handle otherwise trusted keys (that can be imported manually by the user)

    if API.personal_keystore.get_private_key(key.fingerprint) is not None:  # one of our keys
        sys.stderr.write("git-anon: This was signed by one of your identities.\n")
        trusted_uids = key.userids
    else:
        for uid in key.userids:
            if verify_uid(uid, API.trusted_keystore):
                trusted_uids.append(uid)
            else:
                untrusted_uids.append(uid)

    return trusted_uids, untrusted_uids


def deduplicate_uids(uids: Tuple[List[PGPUID], List[PGPUID]]) -> Tuple[List[PGPUID], List[PGPUID]]:
    trusted_uids, untrusted_uids = uids

    trusted_uids_deduplicated: List[PGPUID] = []
    for uid in trusted_uids:
        if uid_not_contained(trusted_uids_deduplicated, uid):
            trusted_uids_deduplicated.append(uid)

    untrusted_uids_deduplicated: List[PGPUID] = []
    for uid in untrusted_uids:
        if uid_not_contained(trusted_uids_deduplicated, uid) and uid_not_contained(untrusted_uids_deduplicated, uid):
            untrusted_uids_deduplicated.append(uid)

    return trusted_uids_deduplicated, untrusted_uids_deduplicated


def uid_not_contained(uids: List[PGPUID], new: PGPUID) -> bool:
    for uid in uids:
        if uid_equals(uid, new):
            return False
    return True


def status_to_user(signature: PGPSignature, key: PGPKey, trusted_uids, untrusted_uids) -> None:
    sys.stderr.write("git-anon: Signature made {}\n".format(signature.created))
    sys.stderr.write("git-anon:                using {} key {}\n".format(
        key.key_algorithm.name, key.fingerprint.keyid)
    )
    sys.stderr.write("git-anon: Good signature with attributes:\n")
    for uid in trusted_uids:
        sys.stderr.write("git-anon:   [trusted] {}\n".format(uid_as_str(uid)))
    for uid in untrusted_uids:
        sys.stderr.write("git-anon:   [unknown] {}\n".format(uid_as_str(uid)))
    sys.stderr.write("Primary key fingerprint: {}\n".format(key.fingerprint))


def status_to_caller(signature: PGPSignature, key: PGPKey, trusted_uids) -> None:
    creation_time: datetime = signature.created
    fingerprint = key.fingerprint.replace(" ", "")
    trust_model = "pgp"
    hash_algo_id = signature.hash_algorithm
    signature_id = "some_signature_id"
    if len(trusted_uids) > 0:
        primary_uid = trusted_uids[0]
    else:
        primary_uid = "Git-Anon User with no trusted UIDs"

    sys.stdout.writelines([
        "[GNUPG:] NEWSIG\n",
        "[GNUPG:] KEY_CONSIDERED {} 0\n".format(fingerprint),
        "[GNUPG:] SIG_ID {} {} {}\n".format(signature_id, creation_time.date(), creation_time.timestamp()),
        "[GNUPG:] KEY_CONSIDERED {} 0\n".format(fingerprint),
        "[GNUPG:] GOODSIG {} {}\n".format(key.fingerprint.keyid, primary_uid),
        "[GNUPG:] VALIDSIG {0} {1} {2} 0 4 22 {3} 00 {0}\n".format(
            fingerprint, creation_time.date(), creation_time.timestamp(), hash_algo_id
        ),
    ])
    if len(trusted_uids) > 0:
        sys.stdout.write("[GNUPG:] TRUST_FULLY 0 {}\n".format(trust_model))


if __name__ == '__main__':
    main()
