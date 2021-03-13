import logging
from copy import copy
from typing import Generator, Optional, Iterable, Tuple, List

from pgpy import PGPKey, PGPUID
from pgpy.types import SorteDeque

from git_anon.anon_config import GitAnonConfig
from git_anon.custom_exception import CustomException
from git_anon.git_config import GitConfig
from git_anon.git_hooks import HooksManager
from git_anon.gpg_general import create_identity as create_identity_internal, uid_is_in, may_certify_any
from git_anon.gpg_general import uid_as_str, uid_equals, may_certify, parse_uid, get_uniform_time_as_datetime
from git_anon.identity import identity_from_keyid, extract_keyid_from_identity, verify_uid
from git_anon.keystores.gpg_keystore_combined import CombinedKeyStore
from git_anon.keystores.gpg_keystore_personal import PersonalKeyStore
from git_anon.keystores.gpg_keystore_shared import SharedKeyStore
from git_anon.keystores.gpg_keystore_trusted import TrustedKeyStore
from git_anon.library_patches.patched_pgpy_functions import patched_pgpy_certify


class APIInterface:
    # pylint: disable=too-many-public-methods
    git_anon_config: GitAnonConfig
    hooks_manager: HooksManager
    git_config: GitConfig

    @property
    def personal_keystore(self) -> PersonalKeyStore:
        return self.git_anon_config.personal_keystore

    @property
    def trusted_keystore(self) -> TrustedKeyStore:
        return self.git_anon_config.trusted_keystore

    @property
    def shared_keystore(self) -> SharedKeyStore:
        return self.git_anon_config.shared_keystore

    @property
    def combined_keystore(self) -> CombinedKeyStore:
        return CombinedKeyStore([self.git_anon_config.shared_keystore, self.personal_keystore])

    def __init__(self, repo_dir: str):
        self.git_anon_config = GitAnonConfig(repo_dir)
        self.git_config = GitConfig(copy(self.git_anon_config.repo))
        self.hooks_manager = HooksManager(self.git_config)

    def use_identity(self, key_id: str, reuse: bool = False) -> None:
        key = self.personal_keystore.get_key(key_id)
        if key is None:
            raise CustomException("Public Key with this ID not available")
        key = self.personal_keystore.get_private_key(key.fingerprint)
        if key is None:
            raise CustomException("Private Key with this ID not available")
        if self.personal_keystore.is_expended(key.fingerprint) and not reuse:
            raise CustomException("Identity is marked as expended/previously used and reuse was not allowed. "
                                  "Use --reuse to explicitly allow it.")
        identity_name, identity_mail = identity_from_keyid(key_id)
        self.git_config.set_user_identity(identity_name, identity_mail, key_id)

    def create_identity(self) -> str:
        pubkey, secret_key = create_identity_internal(self.git_anon_config.userids[0], self.git_anon_config.userids[1:])

        self.shared_keystore.add_key(pubkey)
        self.personal_keystore.store_key(secret_key)

        self._auto_reveal_uids(pubkey)

        certification_requests = [self._extract_matching_uid(pubkey, uid_as_str(u)) for u in pubkey.userids]

        for certification in self.cert_sign_multiple(certification_requests, accept_all_uids=True):
            self.cert_import_single(certification)
            self._auto_reveal_uids(certification)  # reveals the certification if requested

        return pubkey.fingerprint.keyid

    def _auto_reveal_uids(self, key: PGPKey) -> None:
        for uid in key.userids:
            for identity in self.git_anon_config.identities:
                if uid_equals(uid, identity.pgp_uid):
                    if identity.auto_reveal:
                        self.shared_keystore.add_userid(key, uid, identity.auto_reveal_encrypted)

    def list_identities(self) -> List[str]:
        # todo add options to filter for previously unused identities
        # how do we find these identities?
        #   remove the private key when switching to a different one? (UIDs can't be added later)
        #   create a file with their fingerprint in a directory (better)
        # once done also warn in use-identity, that the id has been used before and require --reuse or a prompt
        keyids = []
        for key in self.personal_keystore.list_keys():
            if not key.is_public:
                keyids.append(str(key.fingerprint.keyid))
        return keyids

    @staticmethod
    def _extract_matching_uid(key: PGPKey, uid: str) -> Optional[PGPKey]:
        # pylint: disable=protected-access
        for key_uid in key.userids:
            # todo filter for uids that have not been certified yet
            if uid_as_str(key_uid) == uid:
                key = copy(key)
                key = key.pubkey
                self_sig = key_uid.selfsig
                key_uid._signatures = SorteDeque()
                key_uid |= self_sig
                key._uids = SorteDeque()
                key._uids.insort(key_uid)
                return key
        return None

    def cert_request(self, key_id: str, uid: str) -> PGPKey:
        key = self.personal_keystore.get_key(key_id)
        if key is None:
            raise CustomException("No key with requested key_id found.")
        key = self._extract_matching_uid(key, uid)
        if key is None:
            raise CustomException("Requested key does not have the requested uid.")
        return key

    def cert_multi_request(self, uid: str) -> Generator[PGPKey, None, None]:
        for key in self.personal_keystore.list_keys():
            minimized_key_with_matching_uid = self._extract_matching_uid(key, uid)
            if minimized_key_with_matching_uid is not None:
                yield minimized_key_with_matching_uid

    def cert_import_single(self, key: PGPKey) -> None:
        if len(key.userids) != 1:
            raise CustomException("Certification contained more than one UserID.")
        uid: PGPUID = key.userids[0]
        if len(uid.__sig__) > 2:  # self-signature plus one certification
            logging.error(uid.__sig__)
            raise CustomException("More than one certification included")
        if not key.verify(uid):
            raise CustomException("UserID was not self-signed. This UID does not belong on this key.")
        self.personal_keystore.add_userid(key, uid)

    def cert_sign_multiple(self, keys: Iterable[PGPKey], accepted_uids: List[str] = None,
                           accept_all_uids: bool = False) -> Generator[PGPKey, None, None]:
        available_signature_keys = self.trusted_keystore.list_keys()
        suitable_signature_keys = []
        for cert_key in available_signature_keys:
            if cert_key.is_public:
                # no private key available
                continue
            if accepted_uids is not None:
                # we have a limited set of acceptable uids
                if not may_certify_any(accepted_uids, cert_key):
                    # a key that can not certify these uids is worthless here
                    continue
            suitable_signature_keys.append(cert_key)
        # if len(suitable_signature_keys) == 0:
        #     raise CustomException("No suitable signature keys available.")
        for key in keys:
            for signature_key in suitable_signature_keys:
                certified_key = self._cert_sign_single(key, signature_key, accepted_uids or [], accept_all_uids)
                if certified_key is not None:
                    yield certified_key

    @staticmethod
    def _cert_sign_single(key: PGPKey, signature_key: PGPKey, accepted_uids: List[str],
                          accept_any_uid: bool) -> Optional[PGPKey]:
        key = copy(key)
        if len(key.userids) > 1:
            logging.error(key)
            raise CustomException(
                "Key {} contained more than one UID. Not signing any of them.".format(key.fingerprint))
        key_uid = key.userids[0]
        if not key.verify(key_uid):
            raise CustomException("Not signing UID '{}' on key {} due to missing self-signature."
                                  .format(key_uid, key.fingerprint))
        # The key might contain illegal components but these will simply be passed through for now.
        if uid_is_in(key_uid, accepted_uids) or accept_any_uid:
            if may_certify(key_uid, signature_key):
                certification = patched_pgpy_certify(signature_key, key_uid, created=get_uniform_time_as_datetime())
                key_uid |= certification
                return key
        return None

    def cert_gen_key(self, uids: List[str]) -> Tuple[PGPKey, PGPKey]:
        pgpy_uids = []
        for uid in uids:
            pgpy_uid = parse_uid(uid)
            if pgpy_uid is None:
                raise CustomException("UID '{}' could not be parsed".format(uid))
            pgpy_uids.append(pgpy_uid)
        pub, sec = create_identity_internal(None, pgpy_uids)
        self.trusted_keystore.store_key(sec)
        return pub, sec

    def unmask_identity(self, anonymous_identity: str) -> Tuple[List[str], List[str]]:
        keyid, fingerprint = extract_keyid_from_identity(anonymous_identity)

        key = self.shared_keystore.get_key(keyid, fingerprint)
        if key is None:
            raise CustomException("Unknown Identity: Public Key not found.")
        uids = key.userids
        if len(uids) == 0:
            # this would make the identity malformed as it has to have at least a pseudo uid.
            raise CustomException("Unknown Identity: Identity has no UserIDs")
        unverified_attributes = []
        verified_attributes = []
        for uid in uids:
            if verify_uid(uid, self.trusted_keystore):
                verified_attributes.append(uid_as_str(uid))
            else:
                unverified_attributes.append(uid_as_str(uid))
        return verified_attributes, unverified_attributes

    def reveal_identity(self, key_id: str, encrypted: bool) -> List[str]:
        key = self.personal_keystore.get_key(key_id)
        if key is None:
            raise CustomException("No identity with given id could be found.")
        revealed_uids = []
        for uid in key.userids:
            self.shared_keystore.add_userid(key, uid, encrypted)
            revealed_uids.append(uid_as_str(uid))
        return revealed_uids

    def reveal_name(self, key_id: str, encrypted: bool) -> str:
        """Reveals the primary name or attribute associated with the identity."""
        key = self.personal_keystore.get_key(key_id)
        if key is None:
            raise CustomException("No identity with given id could be found.")
        revealed_uids = []
        for uid in key.userids:
            if uid.is_primary:
                self.shared_keystore.add_userid(key, uid, encrypted)
                revealed_uids.append(uid_as_str(uid))
                # this also accepts previously revealed user ids and reveals them again
                #   (which should not create a new file)
        count = len(revealed_uids)
        if count == 0:
            raise CustomException("No primary Attribute has been added for this identity. "
                                  "Please add it before attempting to reveal it.")
        if count >= 2:
            for uid in revealed_uids:
                logging.warning("Revealed: %s", uid)
            raise RuntimeWarning("We just revealed more than one primary identity.")
        return revealed_uids[0]

    def reveal_attribute(self, key_id: str, attribute: str, encrypted: bool = True) -> List[str]:
        key = self.personal_keystore.get_key(key_id)
        if key is None:
            raise CustomException("No identity with given id could be found.")
        revealed_uids = []
        for uid in key.userids:
            if uid_as_str(uid) == attribute:
                self.shared_keystore.add_userid(key, uid, encrypted)
                revealed_uids.append(uid_as_str(uid))
                # This also accepts previously revealed user ids and reveals them again.
                #   (which should not create a new file)
        if len(revealed_uids) == 0:
            raise CustomException("This attribute has not been added for this identity. "
                                  "Please add it before attempting to reveal it.")
        return revealed_uids

    def update_mailmap(self) -> None:
        self.git_config.enable_mailmap()
        with open(self.git_config.mailmap_file_path, "w") as mailmap_file:
            for key in self.combined_keystore.list_keys():
                for uid in key.userids:
                    if uid.is_primary:
                        email = uid.email if uid.email != "" else "unknown-email"  # empty mails are unsupported by git
                        anon_name, anon_mail = identity_from_keyid(key.fingerprint.keyid)
                        mapping = "{0} <{1}> {2} <{3}>".format(uid.name, email, anon_name, anon_mail)
                        mailmap_file.write(mapping + "\n")

    def config_list_userids(self) -> List[str]:
        return [uid_as_str(a) for a in self.git_anon_config.userids]

    def config_add_uid(self, uid: str, auto_reveal: bool, auto_reveal_encrypted: bool) -> None:
        return self.git_anon_config.add_userid(uid, auto_reveal, auto_reveal_encrypted)

    def config_remove_uid(self, uid: str) -> None:
        return self.git_anon_config.remove_userid(uid)

    def config_set_enc_key(self, enc_key: str):
        return self.git_anon_config.set_enc_key(enc_key)

    def enable(self) -> None:
        self.git_config.set_gpg_home()
        self.git_config.set_value("log", "showSignature", True)
        self.hooks_manager.enable()

    def disable(self) -> None:
        self.git_config.unset_gpg_home()
        self.git_config.unset_user_identity()
        self.git_config.unset_signing_key()
        self.git_config.unset_value("log", "showSignature")
        self.hooks_manager.disable()

    def cert_import_certification_key(self, key: PGPKey) -> None:
        key = copy(key)
        self.trusted_keystore.add_key_and_all_uids(key)
        if not key.is_public:
            self.trusted_keystore.store_key(key)

    def config_set_sync_remote(self, remote_name: str, remote_branch: str) -> None:
        if remote_name is not None:
            self.git_anon_config.set_remote_name(remote_name)
        if remote_branch is not None:
            self.git_anon_config.set_remote_branch(remote_branch)

# todo command for self-certification using external gpg
# option: keyid to use from regular gpg keyring
# consider using gpg for this for compatibility with smartcards, ...
# self-certify all uids where private keys are available
