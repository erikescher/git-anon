from copy import copy
from typing import Optional

from pgpy import PGPKey, PGPUID

from git_anon.keystores.gpg_keystore_personal import PersonalKeyStore


class TrustedKeyStore(PersonalKeyStore):

    def add_key(self, key: PGPKey) -> None:
        # filter for the pubkey only and copy the key object so we don't affect other instances
        key = copy(key.pubkey)

        self._strip_signatures_uids_subkeys(key)

        self._store_primary_key(key)

    def _expected_pseudo_uid(self) -> Optional[PGPUID]:
        return None  # accept only keys that don't have a uid in their primary packet
