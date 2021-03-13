import os
import secrets
import struct
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pgpy import PGPUID, PGPKey

from git_anon.custom_exception import CustomException
from git_anon.keystores.gpg_keystore import KeyStore, sha256
from git_anon.system_interactions.subprocess_utils import run_subprocess_and_return_stdout_as_str


class AuthenticatedEncryptionWrapper:
    aesgcm: AESGCM
    nonce: bytes

    def __init__(self, key: bytes, nonce: bytes):
        self.aesgcm = AESGCM(key)
        self.nonce = nonce

    def encrypt(self, data: bytes) -> bytes:
        return self.aesgcm.encrypt(self.nonce, data, None)

    def decrypt(self, data: bytes) -> bytes:
        return self.aesgcm.decrypt(self.nonce, data, None)


class Padder:
    _header_format = "<I"
    _header_length = 4
    _overall_length: int

    def __init__(self, target_length: int):
        self._overall_length = target_length
        self._data_length = self._overall_length - self._header_length

    def padd(self, data: bytes) -> bytes:
        if len(data) > self._data_length:
            raise AssertionError("Data too long to pad!")
        header = struct.pack(self._header_format, len(data))
        if len(header) != self._header_length:
            raise AssertionError("Unexpected header length!")
        padded_data = header + data + (self._data_length - len(data)) * b"\00"
        return padded_data

    def unpadd(self, data: bytes) -> bytes:
        header = data[:self._header_length]
        length = struct.unpack(self._header_format, header)[0]
        if length > self._data_length:
            raise AssertionError("Unexpected payload length!")
        return data[self._header_length:self._header_length + length]


class KeyDerivationHelper:
    scrypt_n = 2**16
    scrypt_r = 8
    scrypt_p = 1

    def derive_key(self, enc_params_file: str, encryption_key: str, cache_dir_path) -> str:
        with open(enc_params_file, "r") as file:
            scrypt_n = self.scrypt_n
            scrypt_r = self.scrypt_r
            scrypt_p = self.scrypt_p
            salt: str = "default-salt"
            verification_hash: Optional[str] = None
            for _, line in enumerate(file):
                if line.startswith("salt: "):
                    salt = line.replace("salt: ", "").strip()
                if line.startswith("hash: "):
                    verification_hash = line.replace("hash: ", "").strip()
                if line.startswith("scrypt_n: "):
                    scrypt_n = int(line.replace("scrypt_n: ", "").strip())
                if line.startswith("scrypt_r: "):
                    scrypt_r = int(line.replace("scrypt_r: ", "").strip())
                if line.startswith("scrypt_p: "):
                    scrypt_p = int(line.replace("scrypt_p: ", "").strip())
        if verification_hash is None:
            raise CustomException("No hash stored in enc_params file. Can not verify encryption key.")

        cached_derived_key = self._get_cached_derived_key(cache_dir_path, verification_hash)
        if cached_derived_key is not None and \
                KeyDerivationHelper.hash_encryption_key(cached_derived_key) == verification_hash:
            return cached_derived_key

        enc_key: str = KeyDerivationHelper._derive_key(salt, scrypt_n, scrypt_r, scrypt_p, encryption_key)
        enc_key_hashed = KeyDerivationHelper.hash_encryption_key(enc_key)
        if verification_hash != enc_key_hashed:
            raise CustomException("Invalid encryption key provided.")
        self._set_cached_derived_key(cache_dir_path, verification_hash, enc_key)
        return enc_key

    def create_enc_params_file(self, enc_params_file: str, encryption_key: str):
        with open(enc_params_file, "w") as file:
            scrypt_n = self.scrypt_n
            scrypt_r = self.scrypt_r
            scrypt_p = self.scrypt_p
            salt: str = secrets.token_hex(32)
            enc_key: str = KeyDerivationHelper._derive_key(salt, scrypt_n, scrypt_r, scrypt_p, encryption_key)
            verification_hash: str = KeyDerivationHelper.hash_encryption_key(enc_key)
            file.writelines([
                "algo: " + "scrypt" + "\n",
                "scrypt_n: " + str(scrypt_n) + "\n",
                "scrypt_r: " + str(scrypt_r) + "\n",
                "scrypt_p: " + str(scrypt_p) + "\n",
                "salt: " + salt + "\n",
                "hash: " + verification_hash + "\n"
            ])

    @staticmethod
    def hash_encryption_key(encryption_key) -> str:
        return sha256(bytes(encryption_key + "git-anon-encryption-key-validation", "utf-8")).hex()

    @staticmethod
    def _derive_key(salt, scrypt_n, scrypt_r, scrypt_p, encryption_key) -> str:
        return Scrypt(
            salt.encode('utf-8'), length=32, n=scrypt_n, r=scrypt_r, p=scrypt_p
        ).derive(
            encryption_key.encode('utf-8')
        ).hex()

    @staticmethod
    def _get_cached_derived_key(cache_dir_path: str, derived_key_hash: str) -> Optional[str]:
        if cache_dir_path is None:
            return None
        filename = os.path.join(cache_dir_path, "derived_key_" + derived_key_hash)
        if not os.path.isfile(filename):
            return None

        with open(filename, "r") as file:
            return file.readlines()[0]

    @staticmethod
    def _set_cached_derived_key(cache_dir_path: str, derived_key_hash: str, enc_key: str) -> None:
        if cache_dir_path is None:
            return
        os.makedirs(os.path.join(cache_dir_path), exist_ok=True)
        filename = os.path.join(cache_dir_path, "derived_key_" + derived_key_hash)
        with open(filename, "w") as file:
            file.write(enc_key)


class SharedKeyStore(KeyStore):
    # to be used for public key material, public and encrypted user ids and associated certifications
    # backend will be a subdirectory in the repository
    derived_encryption_key: Optional[str] = None
    cache_dir_path: str

    def __init__(self, storage_location: str, cache_dir_path: str, encryption_key: str = None):
        super().__init__(storage_location)
        self.cache_dir_path = cache_dir_path
        if encryption_key is not None:
            self.derived_encryption_key = self._init_encryption(encryption_key)

    def _init_encryption(self, encryption_key: str) -> str:
        storage_location = self.storage_location
        enc_params_file: str
        if storage_location.endswith(os.path.sep):
            enc_params_file = storage_location + "enc_params"
        else:
            enc_params_file = storage_location + os.path.sep + "enc_params"

        if not os.path.isfile(enc_params_file):
            KeyDerivationHelper().create_enc_params_file(enc_params_file, encryption_key)
            self._add_file_to_git(enc_params_file)

        return KeyDerivationHelper().derive_key(enc_params_file, encryption_key, self.cache_dir_path)

    def _get_userid_packets(self, primary_key: PGPKey):
        fingerprint = primary_key.fingerprint
        for uid_folder, filename in self._get_potential_userid_packet_locations(fingerprint):
            encrypted: bool = filename.endswith("-encrypted")

            expected_hash = filename
            expected_hash = expected_hash[:-len("-public")] if expected_hash.endswith("-public") else expected_hash
            expected_hash = expected_hash[:-len("-encrypted")] if expected_hash.endswith(
                "-encrypted") else expected_hash

            with open(os.path.join(uid_folder, filename), "rb") as file:
                contents: bytes = file.read()
            if encrypted:
                contents = self._decrypt_bytes(contents, expected_hash)
            self._verify_and_import_uid_packet(primary_key, contents, expected_hash)

    # pylint: disable=arguments-differ
    def add_userid(self, key: PGPKey, uid: PGPUID, encrypted: bool = False) -> None:

        prepared_uid = self._prepare_uid_for_export(key, uid)
        if prepared_uid is None:
            # no export needed
            return
        filename, serialized_key, serialization_hash = prepared_uid
        # The serialization_hash is calculated before encryption to ensure that encrypted and unencrypted uids can be
        # matched.
        # There might be a risk of revealing a hash of the uid, however the inclusion of the self-signature and it's
        # signature data should mask this sufficiently. If an attacker could predict or guess the signature data of a
        # signature, he could also forge it.

        if encrypted:
            filename += "-encrypted"
            serialized_key = self._encrypt_bytes(serialized_key, serialization_hash)
        else:
            filename += "-public"

        self._write_file(filename, serialized_key)

    def test_encryption_key_valid(self, enc_key: str) -> Tuple[bool, Optional[str]]:
        try:
            _ = self._init_encryption(enc_key)
        except Exception as e:  # pylint: disable=broad-except
            return False, str(e)
        return True, None

    _encryption_integrity_tag_length = 16
    _encrypted_overall_length = 512
    _padded_data_length = _encrypted_overall_length - _encryption_integrity_tag_length

    def _encrypt_bytes(self, data: bytes, filename_based_nonce: str) -> bytes:
        # padding to fixed length to avoid differentiating information
        padded_data = Padder(self._padded_data_length).padd(data)

        encrypted_data = self._get_aes_cipher(filename_based_nonce).encrypt(padded_data)
        if not len(encrypted_data) == self._encrypted_overall_length:
            raise AssertionError("Padding failed: {} != {}".format(len(padded_data), self._encrypted_overall_length))
        return encrypted_data

    def _decrypt_bytes(self, encrypted_data: bytes, filename_based_nonce) -> bytes:
        padded_data = self._get_aes_cipher(filename_based_nonce).decrypt(encrypted_data)

        return Padder(self._padded_data_length).unpadd(padded_data)

    def _get_aes_cipher(self, nonce: str) -> AuthenticatedEncryptionWrapper:
        if self.derived_encryption_key is None:
            raise AssertionError("Cannot encrypt or decrypt without an encryption key!")
        encryption_key: bytes = sha256(bytes(self.derived_encryption_key + "data_encryption", 'utf-8'))
        initialization_vector: bytes = sha256(bytes(nonce, 'utf-8'))[:16]
        if len(encryption_key) != 32:
            raise AssertionError("Unexpected encryption key length!")
        if len(initialization_vector) != 16:
            raise AssertionError("Unexpected initialization vector length!")

        return AuthenticatedEncryptionWrapper(encryption_key, initialization_vector)

    def _write_file(self, filename: str, data: bytes) -> None:
        super()._write_file(filename, data)
        self._add_file_to_git(filename)

    def _add_file_to_git(self, filename: str) -> None:
        run_subprocess_and_return_stdout_as_str(
            ["git", "-c", "core.hooksPath=/dev/null", "add", os.path.abspath(filename)], check_return_code=True
        )
