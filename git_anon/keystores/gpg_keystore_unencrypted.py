import os

# noinspection PyPackageRequirements
from pgpy import PGPUID, PGPKey

from git_anon.keystores.gpg_keystore import KeyStore


class UnencryptedKeyStore(KeyStore):

    def _get_userid_packets(self, primary_key: PGPKey):
        fingerprint = primary_key.fingerprint
        for uid_folder, filename in self._get_potential_userid_packet_locations(fingerprint):
            with open(os.path.join(uid_folder, filename), "rb") as file:
                contents: bytes = file.read()
            self._verify_and_import_uid_packet(primary_key, contents, filename)

    def add_userid(self, key: PGPKey, uid: PGPUID) -> None:
        prepared_uid = self._prepare_uid_for_export(key, uid)
        if prepared_uid is None:
            # no export needed
            return
        filename, serialized_key, _ = prepared_uid

        self._write_file(filename, serialized_key)
