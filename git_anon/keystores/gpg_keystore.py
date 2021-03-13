import os
from abc import ABCMeta, abstractmethod
from copy import copy
from typing import Optional, Tuple, Iterable, List

import pgpy
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from pgpy import PGPKey, PGPUID
from pgpy.types import Fingerprint

from git_anon.custom_exception import CustomException
from git_anon.gpg_general import uid_equals, get_pseudo_uid
from git_anon.gpg_general.key_utils import KeyUtils


def sha256(data: bytes) -> bytes:
    digest = Hash(SHA256())
    digest.update(data)
    return digest.finalize()


class KeyStore(metaclass=ABCMeta):
    # data could be cached in /dev/shm/... to increase performance with many keys

    storage_location: str

    def __init__(self, storage_location: str):
        os.makedirs(storage_location, exist_ok=True)
        os.makedirs(os.path.join(storage_location, "keys"), exist_ok=True)
        self.storage_location = storage_location

    def _get_primary_key(self, keyid: str, fingerprint: Optional[pgpy.pgp.Fingerprint]) -> Optional[PGPKey]:
        possible_location: str
        if fingerprint is not None:
            if fingerprint.keyid != keyid:
                raise CustomException("Keyid does not match with end of provided fingerprint.")
            possible_location = self._folder_for_fingerprint(fingerprint)
        else:
            potential_locations = self._folders_for_keyid(keyid)
            if len(potential_locations) == 0:
                return None
            if len(potential_locations) > 1:
                message = "Found more than one key with id " + keyid + ": keys:"
                for potential_location in potential_locations:
                    fpr = potential_location[:-40]
                    message += "\n  fpr:" + fpr
                message += "Consider yourself lucky. This might be a sensation and is so unlikely that no code was " \
                           "written to handle this situation."
                raise CustomException(message)
            possible_location = potential_locations[0]

        if not os.path.isdir(possible_location):
            # the requested key is not available
            return None

        primary_key_file = os.path.join(possible_location, "primary_key.pub")
        if not os.path.isfile(primary_key_file):
            # the folder exists but the primary key does not
            return None

        key, _ = pgpy.PGPKey.from_file(primary_key_file)

        if not possible_location == self._folder_for_fingerprint(key.fingerprint):
            # the fingerprint does not match the storage location
            return None

        return self._verify_primary_key(key, keyid, fingerprint, self._expected_pseudo_uid())

    def _expected_pseudo_uid(self) -> Optional[PGPUID]:
        return get_pseudo_uid()

    @staticmethod
    def _verify_primary_key(key: PGPKey, expected_keyid: str, expected_fingerprint: Optional[Fingerprint],
                            expected_uid: Optional[PGPUID]):
        if not key.is_public \
                and not KeyStore._verify_expected_fingerprint_and_keyid(key, expected_keyid, expected_fingerprint) \
                and not KeyStore._verify_legal_key_with_single_userid(key, expected_uid is not None) \
                and not KeyStore._verify_expected_uid(key, expected_uid):
            return None

        # primary key has been validated
        return key

    @staticmethod
    def _verify_expected_fingerprint_and_keyid(key: PGPKey, expected_keyid: str,
                                               expected_fingerprint: Optional[Fingerprint]) -> bool:
        if expected_fingerprint is not None:
            # we have an expected fingerprint
            if key.fingerprint != expected_fingerprint:
                # imported key does not match the expected fingerprint; potential attack
                return False

        if key.fingerprint.keyid != expected_keyid:
            # key id does not match requested key id
            return False

        return True

    @staticmethod
    def _verify_expected_uid(key: PGPKey, expected_uid: Optional[PGPUID]) -> bool:
        if expected_uid is not None:
            imported_uid: PGPUID = key.userids[0]
            if not uid_equals(imported_uid, expected_uid):
                # The pseudo uid was not included.
                # A different one might have been used instead.
                return False

            if len(imported_uid.signers) > 1:
                # more than one self-signature or a certification included
                return False

        return True

    @staticmethod
    def _verify_no_subkeys_signers_revsigs(key: PGPKey) -> bool:
        if len(key.subkeys) != 0:
            # Subkeys were included.
            return False

        if len(key.signers) != 0:
            # Direct signatures over the key were included.
            return False

        for _ in key.revocation_signatures:
            # A revocation signature was included.
            return False

        return True

    @staticmethod
    def _verify_legal_key_with_single_userid(key: PGPKey, single_uid_expected: bool = True) -> bool:
        if single_uid_expected:
            if not len(key.userids) == 1:
                # more than just one  user id included
                return False

            single_uid: PGPUID = key.userids[0]

            if not single_uid.is_uid:
                # photo uids are not supported
                return False

            verification_result = key.verify(single_uid)
            if not verification_result:
                # no valid self-signature on this key
                return False
        else:
            if len(key.userids) != 0:
                # did not expect a userid
                return False

        if not KeyStore._verify_no_subkeys_signers_revsigs(key):
            return False

        return True

    def _get_potential_userid_packet_locations(self, fingerprint: Fingerprint) -> List[Tuple[str, str]]:
        key_folder = self._folder_for_fingerprint(fingerprint)
        uid_folder = os.path.join(key_folder, "uid-packets")

        if not os.path.isdir(uid_folder):
            # no other uids available
            return []

        potential_locations: List[Tuple[str, str]] = []
        for file in os.listdir(uid_folder):
            if os.path.isfile(os.path.join(uid_folder, file)):
                potential_locations.append((uid_folder, file))
        return potential_locations

    @staticmethod
    def _transplant_uid(donor_uid: PGPUID, target_key: PGPKey) -> None:
        if not donor_uid.is_uid:
            raise AssertionError("Donor UID is not a UID and cannot be transplanted!")
        donor_uid = donor_uid.__copy__()
        target_key.add_uid(donor_uid, selfsign=False)

    def add_key(self, key: PGPKey) -> None:
        # filter for the pubkey only and copy the key object so we don't affect other instances
        key = copy(key.pubkey)

        # remove all user ids except the pseudo uid
        key = self._filter_uids_on_key(key, get_pseudo_uid())
        KeyUtils.strip_subkeys(key)
        if len(key.userids[0].signers) != 1:
            raise AssertionError("Certifications on pseudo UIDs are not allowed!")

        self._store_primary_key(key)

    def _store_primary_key(self, key: PGPKey) -> None:
        folder = self._folder_for_fingerprint(key.fingerprint)
        os.makedirs(folder, exist_ok=True)
        filename = os.path.join(folder, "primary_key.pub")
        self._write_file(filename, bytes(str(key), 'utf-8'))

    @staticmethod
    def _filter_uids_on_key(key: PGPKey, desired_uid: PGPUID) -> PGPKey:
        key = copy(key)

        # remove all user ids except the pseudo uid
        for uid in key.userids:
            if not uid_equals(uid, desired_uid):
                key.del_uid(uid.name)

        # assert that no unwanted information is left
        if len(key.userids) != 1 or not uid_equals(key.userids[0], desired_uid):
            raise AssertionError("Unwanted information left on the key!")
        for _ in key.revocation_signatures:
            raise AssertionError("Keys should not have revocation signatures!")
        if len(key.signers) != 0:
            raise AssertionError("Keys should not be signed directly!")

        return key

    def _folder_for_fingerprint(self, fingerprint: pgpy.pgp.Fingerprint) -> str:
        # Using the key-id allows us to blindly change into the correct folder based on the signers keyid that is always
        # included in the signature. The fingerprint is needed for collision resistance but isn't always included in
        # signatures. Where the fingerprint is unknown we'll iterate over the subdirectories for the keyid.
        return os.path.join(self.storage_location, "keys", fingerprint.keyid, fingerprint.replace(" ", ""))

    def _folders_for_keyid(self, keyid: str) -> List[str]:
        if len(keyid) != 16:
            raise AssertionError("64bit key ids are required!")
        keyid_folder = os.path.join(self.storage_location, "keys", keyid)
        if not os.path.isdir(keyid_folder):
            return []
        potential_folders = []
        for file_or_folder in os.listdir(keyid_folder):
            fingerprint_folder = os.path.join(keyid_folder, file_or_folder)
            if len(file_or_folder) == 40 and os.path.isdir(fingerprint_folder):
                potential_folders.append(fingerprint_folder)
        return potential_folders

    def get_key(self, keyid: str, fingerprint: pgpy.pgp.Fingerprint = None) -> Optional[PGPKey]:
        if len(keyid) != 16:
            raise AssertionError("64bit key ids are required!")
        if not (fingerprint is None or isinstance(fingerprint, Fingerprint)):
            raise AssertionError("Fingerprints must be instances of the Fingerprint class if provided!")

        primary_key = self._get_primary_key(keyid, fingerprint)
        if primary_key is None:
            return None
        combined_key = primary_key.__copy__()

        self._get_userid_packets(combined_key)
        return combined_key

    @abstractmethod
    def _get_userid_packets(self, primary_key):
        pass

    @abstractmethod
    def add_userid(self, key: PGPKey, uid: PGPUID):
        pass

    def _prepare_uid_for_export(self, key: PGPKey, uid: PGPUID) -> Optional[Tuple[str, bytes, str]]:
        # ultimately we should separate uids. self-signatures and certifications and store them in individual files
        # uids and self-signatures can likely be stored together
        # for now we might have to store keys with one uid and associated self-signatures and certifications together
        #    for compatibility with libraries and gpg itself

        # filter for the pubkey only and copy the key object so we don't affect other instances
        key = copy(key.pubkey)

        # abort if presented with the pseudo-uid to export
        if uid_equals(uid, get_pseudo_uid()):
            # the pseudo-uid is exported together with the primary key material and does not need to be exported again
            return None

        # filter the key to only requested information
        key = self._filter_uids_on_key(key, uid)
        if len(key.userids) != 1:
            raise AssertionError("Only one UID should remain!")

        # export the key
        serialized_key: bytes = bytes(key)

        key_folder = self._folder_for_fingerprint(key.fingerprint)
        uid_folder = os.path.join(key_folder, "uid-packets")
        os.makedirs(uid_folder, exist_ok=True)
        serialization_hash: str = sha256(serialized_key).hex()
        filename = os.path.join(uid_folder, serialization_hash)

        return filename, serialized_key, serialization_hash

    def _write_file(self, filename: str, data: bytes) -> None:
        if os.path.isfile(filename):
            # We already stored this exact serialized packet.
            with open(filename, "rb") as file:
                if not file.read() == data:
                    raise CustomException(
                        "Writing to {} failed. File already exists but contents are not as expected.".format(filename))
            return
        with open(filename, "wb") as file:
            file.write(data)

    def _verify_and_import_uid_packet(self, primary_key: PGPKey, uid_packet: bytes, expected_hash: str) -> None:
        actual_serialized_hash = sha256(uid_packet).hex()

        if not actual_serialized_hash == expected_hash:
            # hashes for the content do not match
            return

        imported_key, _ = PGPKey.from_blob(uid_packet)

        if not imported_key.fingerprint == primary_key.fingerprint:
            # Primary key material on the two keys does not match. They don't belong together.
            return

        if not KeyStore._verify_legal_key_with_single_userid(imported_key):
            # key failed one of the validity tests
            return

        if not primary_key.verify(imported_key.userids[0]):
            # Primary key did not sign userid.
            # This check was already performed via the self-signature check on imported_key and the fingerprint
            # match with primary_key before.
            return

        new_userid: PGPUID = imported_key.userids[0]
        self._transplant_uid(new_userid, primary_key)

    def list_keys(self) -> Iterable[PGPKey]:
        if not os.path.isdir(self.storage_location):
            # no keys present
            yield []
            return
        for keyid in os.listdir(os.path.join(self.storage_location, "keys")):
            key = self.get_key(keyid)
            if key is not None:
                yield key

    @staticmethod
    def _strip_signatures_uids_subkeys(key: PGPKey):
        # overwrite internal variables in the key to remove unnecessary information
        KeyUtils.strip_subkeys(key)
        KeyUtils.strip_uids(key)
        KeyUtils.strip_signatures(key)

    @staticmethod
    def _combine_key_parts(key_parts: List[PGPKey]) -> PGPKey:
        # pylint: disable=protected-access
        final_key = None

        for part in key_parts:
            if part is None:
                continue
            if final_key is None:
                # first key part
                final_key = copy(part)
                continue
            if not part.fingerprint == final_key.fingerprint:
                raise CustomException("Fingerprints don't match for key parts to be combined.")
            if final_key.is_public and not part.is_public:
                old_final_key = copy(final_key)
                # noinspection PyProtectedMember
                final_key._key = copy(part._key)
                final_key.pubkey = old_final_key
            for uid in part.userids:
                final_key |= uid
            for sig in part.__sig__:
                final_key |= sig
            for subkey in part.subkeys:
                final_key |= subkey

        return final_key
