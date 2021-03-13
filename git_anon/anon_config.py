import json
import os
from typing import Optional, List

from git import Repo
from pgpy import PGPUID

from git_anon.anon_identity import GitAnonIdentity
from git_anon.custom_exception import CustomException
from git_anon.gpg_general import uid_equals, parse_uid
from git_anon.keystores.gpg_keystore_personal import PersonalKeyStore
from git_anon.keystores.gpg_keystore_shared import SharedKeyStore
from git_anon.keystores.gpg_keystore_trusted import TrustedKeyStore


class GitAnonConfig:
    repo: Repo
    git_dir: str
    shared_keystore: SharedKeyStore
    trusted_keystore: TrustedKeyStore
    personal_keystore: PersonalKeyStore
    identities: List[GitAnonIdentity]

    @property
    def userids(self):  # the first userid will be considered the primary and should be the users name
        return [i.pgp_uid for i in self.identities]

    def __init__(self, repo_dir: str):
        self.repo = Repo(repo_dir)
        self.git_dir = self.repo.git_dir

        self.identity_encryption_key = self._get_config_encryption_key(self.repo.git_dir)

        public_keystore_path = os.path.abspath(os.path.join(self.repo.working_dir, ".git-anon/keystore"))
        cache_dir_path = os.path.abspath(os.path.join(self.repo.git_dir, "git-anon", "shared_keystore"))
        self.shared_keystore = SharedKeyStore(public_keystore_path, cache_dir_path, self.identity_encryption_key)

        trusted_keystore_path = os.path.abspath(
            os.path.join(self.repo.git_dir, "git-anon", "trusted-certification-keys"))
        self.trusted_keystore = TrustedKeyStore(trusted_keystore_path)

        personal_keystore_path = os.path.abspath(os.path.join(self.repo.git_dir, "git-anon", "personal-keys"))
        self.personal_keystore = PersonalKeyStore(personal_keystore_path)

        self.identities = self._get_config_userids(self.repo.git_dir)

    @staticmethod
    def _get_config_encryption_key(git_dir: str) -> Optional[str]:
        filename = os.path.join(git_dir, "git-anon", "enc_key")
        if not os.path.isfile(filename):
            return None

        with open(filename, "r") as file:
            lines = file.readlines()

        return lines[0]

    @staticmethod
    def _get_config_userids(git_dir: str) -> List[GitAnonIdentity]:
        filename = os.path.join(git_dir, "git-anon", "identities.json")
        if not os.path.isfile(filename):
            return []

        with open(filename, "r") as file:
            try:
                json_root = json.load(file)
            except json.decoder.JSONDecodeError:
                return []

        identities: List[GitAnonIdentity] = []
        try:
            json_uids = json_root["uids"]
        except KeyError:
            return []

        for json_uid in json_uids:
            identity = GitAnonIdentity.from_dict(json_uid)
            uid = identity.pgp_uid
            if uid is not None and not GitAnonConfig._uid_present([i.pgp_uid for i in identities], uid):
                identities.append(identity)

        return identities

    @staticmethod
    def _encode_json_uid(pgp_uid: PGPUID) -> dict:
        auto_reveal = False
        encrypted = True
        identity = GitAnonIdentity(pgp_uid, auto_reveal, encrypted)
        return identity.to_dict()

    def _get_identities_filename(self):
        os.makedirs(os.path.join(self.git_dir, "git-anon"), exist_ok=True)
        filename = os.path.join(self.git_dir, "git-anon", "identities.json")
        if not os.path.isfile(filename) or os.path.getsize(filename) == 0:
            with open(filename, "w") as file:
                file.write("{}")
        return filename

    @staticmethod
    def _uid_present(uids: List[PGPUID], new_uid: PGPUID) -> bool:
        for existing_uid in uids:
            if uid_equals(existing_uid, new_uid):
                return True
        return False

    def add_userid(self, user_id: str, auto_reveal: bool, auto_reveal_encrypted: bool) -> None:
        self.remove_userid(user_id)  # to avoid duplicates (and overwrite old settings)
        filename = self._get_identities_filename()
        uid = parse_uid(user_id)

        uid_dict = GitAnonIdentity(uid, auto_reveal, auto_reveal_encrypted).to_dict()

        with open(filename, "r") as file:
            try:
                json_object = json.load(file)
            except json.decoder.JSONDecodeError:
                json_object = {}
            try:
                json_object['uids']
            except KeyError:
                json_object['uids'] = []
            json_object['uids'].append(uid_dict)
        with open(filename, "w") as file:
            json.dump(json_object, file)

    def remove_userid(self, user_id: str) -> None:
        filename = self._get_identities_filename()
        uid_to_remove = parse_uid(user_id)
        with open(filename, "r") as file:
            json_object = json.load(file)
        json_object['uids'] = []
        for existing_identity in self.identities:
            if not uid_equals(uid_to_remove, existing_identity.pgp_uid):
                json_object['uids'].append(existing_identity.to_dict())
        with open(filename, "w") as file:
            json.dump(json_object, file)

    def set_enc_key(self, enc_key: str) -> None:
        os.makedirs(os.path.join(self.git_dir, "git-anon"), exist_ok=True)
        filename = os.path.join(self.git_dir, "git-anon", "enc_key")
        success, failure_reason = self.shared_keystore.test_encryption_key_valid(enc_key)
        if not success:
            raise CustomException("Failed to verify key: ", failure_reason)
        with open(filename, "w") as file:
            file.write(enc_key)

    def set_remote_name(self, remote_name: str) -> None:
        os.makedirs(os.path.join(self.git_dir, "git-anon"), exist_ok=True)
        filename = os.path.join(self.git_dir, "git-anon", "remote_name")
        with open(filename, "w") as file:
            file.write(remote_name)

    def set_remote_branch(self, remote_branch: str) -> None:
        os.makedirs(os.path.join(self.git_dir, "git-anon"), exist_ok=True)
        filename = os.path.join(self.git_dir, "git-anon", "remote_branch")
        with open(filename, "w") as file:
            file.write(remote_branch)
