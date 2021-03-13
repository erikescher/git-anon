import os
from copy import copy
from typing import Optional, List

from pgpy import PGPKey
# noinspection PyProtectedMember
from pgpy.pgp import Fingerprint

from git_anon.custom_exception import CustomException
from git_anon.keystores.gpg_keystore_unencrypted import UnencryptedKeyStore


class PersonalKeyStore(UnencryptedKeyStore):

    def add_key_and_all_uids(self, key: PGPKey) -> None:
        self.add_key(key)
        for uid in key.userids:
            self.add_userid(key, uid)

    def store_key(self, key: PGPKey) -> None:
        key = copy(key)
        self.add_key_and_all_uids(key)
        key_file = self._get_private_key_location(key.fingerprint)

        self._strip_signatures_uids_subkeys(key)

        if key.is_protected:
            raise CustomException("Protected/Encrypted keys are currently not supported.")

        key_encoded: bytes = bytes(str(key), "utf-8")
        self._write_file(key_file, key_encoded)

    def get_private_key(self, fingerprint: str) -> Optional[PGPKey]:
        expected_fingerprint = Fingerprint(fingerprint)
        key_file = self._get_private_key_location(expected_fingerprint)

        try:
            key, _ = PGPKey.from_file(key_file)
        except FileNotFoundError:
            return None

        if not key.fingerprint == expected_fingerprint:
            raise CustomException("Actual fingerprint for stored private key does not match expected one. ({})".format(
                expected_fingerprint))
        self._strip_signatures_uids_subkeys(key)

        pubkey = self.get_key(key.fingerprint.keyid, key.fingerprint)
        if pubkey is None:
            raise CustomException(
                "Missing public key for fingerprint {}, while private is available".format(expected_fingerprint))
        return self._combine_key_parts([pubkey, key])

    def _get_private_key_location(self, fingerprint: Fingerprint) -> str:
        key_folder = self._folder_for_fingerprint(fingerprint)
        return os.path.join(key_folder, "private_key")

    def set_expended(self, fingerprint: Fingerprint, value: bool = True):
        self._set_bool_key_property(fingerprint, "expended", value)

    def is_expended(self, fingerprint: Fingerprint) -> bool:
        return self._get_bool_key_property(fingerprint, "expended", default=False)

    def _set_bool_key_property(self, fingerprint: Fingerprint, property_name: str, value: bool) -> None:
        if value:
            encoded_value = bytes("True", "utf-8")
        else:
            encoded_value = bytes("False", "utf-8")
        self._write_file(self._get_property_filename(fingerprint, property_name), encoded_value)

    def _get_bool_key_property(self, fingerprint: Fingerprint, property_name: str, default: bool = False) -> bool:
        property_filename = self._get_property_filename(fingerprint, property_name)
        if os.path.isfile(property_filename):
            with open(property_filename, "r") as file:
                if file.read() == bytes("True", "utf-8"):
                    return True
                if file.read() == bytes("False", "utf-8"):
                    return False
        return default

    def _get_property_filename(self, fingerprint: Fingerprint, property_name: str) -> str:
        key_folder = self._folder_for_fingerprint(fingerprint)
        return os.path.join(key_folder, "property_" + property_name)

    def list_keys(self) -> List[PGPKey]:
        combined_keys = []
        for pubkey in super().list_keys():
            private_key = self.get_private_key(pubkey.fingerprint)
            combined_keys.append(self._combine_key_parts([pubkey, private_key]))
        return combined_keys
