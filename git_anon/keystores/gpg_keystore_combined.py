from typing import Optional, List, Dict

from pgpy import PGPKey
from pgpy.types import Fingerprint

from git_anon.keystores.gpg_keystore import KeyStore


class CombinedKeyStore(KeyStore):
    def _get_userid_packets(self, primary_key):
        raise NotImplementedError("This function should not be needed.")

    keystores: List[KeyStore]

    def add_key(self, key: PGPKey) -> None:
        raise NotImplementedError("This function is not actually available on this instance")

    def add_userid(self, key, uid):
        raise NotImplementedError("This function is not actually available on this instance")

    def get_key(self, keyid: str, fingerprint: Fingerprint = None) -> Optional[PGPKey]:
        retrieved_keys: List[PGPKey] = []
        for keystore in self.keystores:
            retrieved_keys.append(keystore.get_key(keyid, fingerprint))
        return self._combine_key_parts(retrieved_keys)

    def list_keys(self) -> List[PGPKey]:
        collected_keys: Dict[Fingerprint, List[PGPKey]] = {}
        for keystore in self.keystores:
            for key in keystore.list_keys():
                if collected_keys.get(key.fingerprint) is None:
                    collected_keys[key.fingerprint] = []
                collected_keys[key.fingerprint].append(key)

        combined_keys: List[PGPKey] = []
        for key_parts in collected_keys.values():
            key = self._combine_key_parts(key_parts)
            combined_keys.append(key)
        return combined_keys

    # noinspection PyMissingConstructor
    # pylint:disable=super-init-not-called
    def __init__(self, keystores: List[KeyStore]):
        self.keystores = keystores
        # super.__init__() deliberately not called. This would initialize directories that are not needed.
