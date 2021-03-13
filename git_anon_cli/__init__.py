import logging
import os
import sys
from io import TextIOWrapper
from typing import Iterable, Generator, List

import click
from pgpy import PGPKey

from git_anon.api_functions import APIInterface
from git_anon.custom_exception import CustomException

API: APIInterface


def _parse_keys_from_list_of_lines(lines: Iterable[str]) -> Generator[PGPKey, None, None]:
    start_markers = ["-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----"]
    end_markers = ["-----END PGP PUBLIC KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"]
    current_token: str = ""
    for line in lines:
        if line.endswith("\n"):
            line = line.rstrip("\n")
        for start_marker in start_markers:
            if line == start_marker:
                current_token = ""  # nosec
        current_token += line + "\n"
        for end_marker in end_markers:
            if line == end_marker:
                yield PGPKey.from_blob(current_token)[0]


def _determine_loglevel() -> int:
    loglevel: int = logging.WARNING
    env = os.environ.get("GIT_ANON_LOGLEVEL")
    if env is not None:
        loglevel = int(env)
        if loglevel <= 6:
            loglevel *= 10
    return loglevel


def _configure_logging() -> None:
    # noinspection PyArgumentList
    logging.basicConfig(
        format='%(levelname)s: %(message)s',
        level=_determine_loglevel(),
        force=True
    )
    logging.debug("Debug logging enabled.")


@click.group()
def cli():
    _configure_logging()
    # we deliberately want to set the following global variables in this function
    global API

    API = APIInterface(".")


@cli.command()
@click.option('--count', default=1)
def create_identity(count: int = 1) -> None:
    """Creates a new identity and returns it's id."""
    for _ in range(count):
        keyid = API.create_identity()
        print(keyid)


@cli.command()
def new_identity() -> None:
    """Creates a new identity and then switches to it."""
    API.use_identity(API.create_identity(), reuse=False)


@cli.command()
@click.argument('key-id')
@click.option('--reuse/--no-reuse', default=False)
def use_identity(key_id: str, reuse: bool = False) -> None:
    """Configures git to use the identity provided as KEY-ID."""
    return API.use_identity(key_id, reuse)


@cli.command()
def list_identities() -> None:
    """Lists all available identities."""
    for keyid in API.list_identities():
        print(keyid)


@cli.command()
def enable() -> None:
    API.enable()


@cli.command()
def disable() -> None:
    API.disable()


@cli.command()
@click.option("--verified-only", default=False, type=click.BOOL)
@click.option("--show-verification", default=True, type=click.BOOL)
@click.argument("identity", type=click.STRING)
def unmask_identity(identity: str, verified_only: bool = False, show_verification: bool = True):
    """ Provides all known attributes for the given IDENTITY. \n
    Attributes will be prepended with either "[verified]" or "[unverified]" depending on trusted certifications."""
    verified_attributes, unverified_attributes = API.unmask_identity(identity)

    for va in verified_attributes:
        verification_tag = "[verified] " if show_verification else ""
        print(verification_tag, va, sep="")

    if not verified_only:
        for ua in unverified_attributes:
            verification_tag = "[unverified] " if show_verification else ""
            print(verification_tag, ua, sep="")


@cli.command()
@click.argument('key-id')
@click.option("--encrypted", default=True, type=click.BOOL)
def reveal_identity(key_id: str, encrypted: bool = True) -> None:
    """Reveals all attributes about the given identity."""
    for uid in API.reveal_identity(key_id, encrypted):
        print("[revealed]", uid)


@cli.command()
@click.argument('key-id')
@click.argument('attribute')
@click.option("--encrypted", default=True, type=click.BOOL)
def reveal_attribute(key_id: str, attribute: str, encrypted: bool = True) -> None:
    for revealed_uid in API.reveal_attribute(key_id, attribute, encrypted):
        print("[revealed]", revealed_uid)


@cli.command()
@click.argument('key-id')
@click.option("--encrypted", default=True, type=click.BOOL)
def reveal_name(key_id: str, encrypted: bool = True):
    """Reveals the primary name or attribute associated with the identity."""
    revealed_uid = API.reveal_name(key_id, encrypted)
    print("[revealed]", revealed_uid)


@cli.command()
def update_mailmap() -> None:
    """Updates the file used by git to map names to anonymous identities."""
    API.update_mailmap()


@cli.command()
@click.pass_context
def update_mappings(click_context):
    """Alias for update-mailmap."""
    click_context.forward(update_mailmap)


@cli.group()
def config() -> None:
    """Group of commands that alter the configuration of Git-Anon."""
    return


@config.command()
@click.argument("user_id")
@click.option("--auto-reveal/--no-auto-reveal", default=False)
@click.option("--encrypted/--public", default=True)
def add_userid(user_id: str, auto_reveal, encrypted) -> None:
    """Adds the given USER-ID to the list of ids for new keys."""
    # todo more flexibility in combining auto-reveal and enc-keys and managing identities
    API.config_add_uid(user_id, auto_reveal, encrypted)


@config.command()
@click.argument("remote-name")
@click.argument("remote-branch")
def config_set_sync_remote(remote_name: str, remote_branch: str) -> None:
    API.config_set_sync_remote(remote_name, remote_branch)


@config.command()
def list_userids() -> None:
    """Lists all attributes that will be added for new keys."""
    for uid in API.config_list_userids():
        print(uid)


@config.command()
@click.argument("user_id")
def remove_userid(user_id: str) -> None:
    """Removes the given attribute from the list of ids for new keys."""
    API.config_remove_uid(user_id)


@config.command()
@click.argument("enc_key")
def set_enc_key(enc_key: str) -> None:
    API.config_set_enc_key(enc_key)


@cli.group()
def cert() -> None:
    """Group of commands that deal with certifications."""
    return


@cert.command(name="sign")
@click.option("--uid", "-u", required=True, multiple=True)
@click.option("--input", "input_file", type=click.File("r"), default="-")
@click.option("--output", "output_file", type=click.File("w"), default="-")
def cert_sign(uid: List[str], input_file: TextIOWrapper, output_file: TextIOWrapper) -> None:
    for key in API.cert_sign_multiple(_parse_keys_from_list_of_lines(input_file.readlines()), uid):
        output_file.write(str(key))


@cert.command(name="request")
@click.option("--uid", "-u", required=True)
@click.option("--keyid", required=True)
@click.option("--output", "output_file", type=click.File("w"), default="-")
def cert_request(uid: str, keyid: str, output_file: TextIOWrapper) -> None:
    key = API.cert_request(keyid, uid)
    if key is None:
        raise CustomException("No key with this key_id and uid found.")
    output_file.write(str(key))


@cert.command(name="multi-request")
@click.option("--uid", "-u", required=True)
@click.option("--output", "output_file", type=click.File("w"), default="-")
def cert_multi_request(uid: str, output_file: TextIOWrapper) -> None:
    for key in API.cert_multi_request(uid):
        output_file.write(str(key))


@cert.command(name="import")
@click.option("--input", "input_file", type=click.File("r"), default="-")
def cert_import(input_file: TextIOWrapper) -> None:
    for key in _parse_keys_from_list_of_lines(input_file.readlines()):
        API.cert_import_single(key)


@cert.command(name="trust")
@click.option("--input", "input_file", type=click.File("r"), default="-")
def cert_trust(input_file: TextIOWrapper) -> None:
    # todo require user to provide all acceptable uids as parameters
    for key in _parse_keys_from_list_of_lines(input_file.readlines()):
        if not key.is_public and key.is_protected:
            raise CustomException("Encrypted/Protected keys are not supported. Remove protection before importing.")
        API.cert_import_certification_key(key)


# todo accept protected private keys and decrypt them
# since pgpy does not support this maybe we can re-encrypt them using a secret stored in the users home directory
# and then use this to unlock them before use everywhere?

# @cert.command(name="trust-with-passphrase")
# @click.option("--input", type=click.File("r"), default="-")
# @click.option('--password', prompt=True, hide_input=True, confirmation_prompt=False)
# def cert_trust_with_passphrase(input: TextIOWrapper, password: str = None) -> None:
#    # require user to provide all acceptable uids as parameters
#    for key in _parse_keys_from_list_of_lines(input.readlines()):
#        if key.is_protected:
#            if password is None:
#                raise CustomException("Password required but none provided.")
#            print("protected:", str(key), sep="\n")
#            protected_key = str(key)
#            with key.unlock(password) as upkey:
#                upkeyc = copy(upkey)
#                print("unprotected:", str(upkeyc), sep="\n")
#                unprotected_key = str(upkeyc)
#            print("EQUAL:", protected_key == unprotected_key)
#            del password
#        else:
#            print("unprotected")
#        # api.cert_import_certification_key(key)


@cert.command(name="gen-key")
@click.option("--uid", required=True)
@click.option("--output", "output_file", type=click.File("w"), default="-")
@click.option("--output-secret-key", "output_secret_file", type=click.File("w"))
def cert_gen_key(uid: str, output_file: TextIOWrapper, output_secret_file: TextIOWrapper) -> None:
    pub, sec = API.cert_gen_key([uid])
    output_file.write(str(pub))
    if output_secret_file is not None:
        output_secret_file.write(str(sec))


@cli.group()
def debug() -> None:
    pass


@debug.command()
def throw() -> None:
    raise CustomException("Test Exception", "Second")


@debug.command()
def environment() -> None:
    print(str(os.environ)[8:-1])


def main() -> None:
    try:
        cli()
    except CustomException as e:
        message: str = ""
        for arg in e.args:
            message += "\n" + str(arg)
        logging.error(message)
        if os.environ.get("GIT_ANON_RETHROW_EXCEPTIONS") == "True":
            raise
        sys.exit(1)

# todo catch InvalidGitRepositoryError and provide a more pleasant exception message
#   differentiate between main repo and git-anon-keys repo

# todo allow auto-completion of key_ids

# todo list known key_ids

# todo allow adding attributes to existing identities


if __name__ == '__main__':
    main()
