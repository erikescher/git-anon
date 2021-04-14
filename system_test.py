import json
import os
import random
import subprocess
from typing import Tuple, List
from unittest import TestCase


def _run_subprocess(args: List[str], check: bool = True) -> Tuple[str, str]:
    prefix: str = "SUBPROCESS: "
    for arg in args:
        prefix += arg + " "
    process = subprocess.run(
        args, check=False, text=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    _print_multiline_with_prefix(prefix + "OUT", process.stdout)
    _print_multiline_with_prefix(prefix + "ERR", process.stderr)

    if check:
        process.check_returncode()

    return process.stdout, process.stderr


def verify_install_executable_on_path():
    _run_subprocess(["git-anon", "--help"], check=True)
    _run_subprocess(["git", "anon", "--help"], check=True)


def _assert_string_contains_all(string: str, expected: List[str]) -> None:
    for e in expected:
        assert string.find(e) != -1, "Failed to find " + e + " in " + string


def verify_command_enable():
    _run_subprocess(["git", "anon", "enable"], check=True)

    hooks = ["post-commit", "post-merge"]
    for hook in hooks:
        hook_file_path = os.path.join(".git", "hooks", hook)
        assert os.path.isfile(hook_file_path), "Failed to find hook " + hook
        assert os.stat(hook_file_path).st_mode & 0o700 == 0o700
        with open(hook_file_path, "r") as file:
            lines = file.readlines()
            assert lines[0].startswith("#!/bin/bash") or lines[0].startswith("#!/bin/sh")
            _assert_string_contains_all(lines[1], ["git-anon"])

    config_options = _run_subprocess(["git", "config", "--list"])[0].splitlines()
    show_signature = False
    gpg_program = False
    for option in config_options:
        print("GIT CONFIG OPTION:", option)
        if option == "gpg.program=" + "helper-for-git-anon":
            gpg_program = True
        if option == "log.showsignature=True":
            show_signature = True
    assert show_signature
    assert gpg_program


def verify_command_config_set_enc_key():
    test_secret = "secret-for-testing"
    _run_subprocess(
        ["git", "anon", "config", "set-enc-key", test_secret],
        check=True
    )
    key_file_path = os.path.join(".git", "git-anon", "enc_key")
    assert os.path.isfile(key_file_path)
    with open(key_file_path, "r") as file:
        assert file.read() == test_secret


def verify_commands_userid():
    test_secret = "secret-for-testing"
    _run_subprocess(["git", "anon", "config", "set-enc-key", test_secret])
    _run_subprocess(["git", "anon", "config", "add-userid", "--auto-reveal", "--encrypted", "Samwell Tarly"])
    _run_subprocess(["git", "anon", "config", "add-userid", "--auto-reveal", "Member of the Nights Watch"])
    _run_subprocess(["git", "anon", "config", "add-userid", "To be deleted later"])
    _run_subprocess(["git", "anon", "config", "add-userid", "Grand Maester of the Nights Watch"])
    _run_subprocess(["git", "anon", "config", "remove-userid", "To be deleted later"])
    identities_file = os.path.join(".git", "git-anon", "identities.json")
    assert os.path.isfile(identities_file)
    with open(identities_file, "r") as file:
        identities_json = json.load(file)
    expected_json = """
    {
      "uids": [
        {
          "name": "Samwell Tarly",
          "comment": "",
          "email": "",
          "auto_reveal": true,
          "auto_reveal_encrypted": true
        },
        {
          "name": "Member of the Nights Watch",
          "comment": "",
          "email": "",
          "auto_reveal": true,
          "auto_reveal_encrypted": true
        },
        {
          "name": "Grand Maester of the Nights Watch",
          "comment": "",
          "email": "",
          "auto_reveal": false,
          "auto_reveal_encrypted": true
        }
      ]
    }
    """
    print(identities_json)
    assert identities_json == json.loads(expected_json)

    lines = _run_subprocess(["git", "anon", "config", "list-userids"])[0].splitlines()
    assert len(lines) == 3
    assert lines[0] == "Samwell Tarly"
    assert lines[1] == "Member of the Nights Watch"
    assert lines[2] == "Grand Maester of the Nights Watch"


def verify_commands_identity_creation_and_setup():
    keyid = _run_subprocess(["git", "anon", "create-identity"])[0].splitlines()[0]
    assert len(keyid) == 16

    _run_subprocess(["git", "anon", "use-identity", keyid])
    configured_signing_key = _run_subprocess(["git", "config", "user.signingkey"])[0].splitlines()[0]
    assert keyid == configured_signing_key
    configured_name = _run_subprocess(["git", "config", "user.name"])[0].splitlines()[0]
    _assert_string_contains_all(configured_name, ["ANON", keyid])
    configured_email = _run_subprocess(["git", "config", "user.email"])[0].splitlines()[0]
    _assert_string_contains_all(configured_email, ["@git-anon", keyid])


def _commit_with_new_identity() -> Tuple[str, str]:
    _run_subprocess(["git", "anon", "new-identity"])
    stdout, _ = _run_subprocess(["git", "commit", "-m", "test_commit", "--allow-empty"])
    commit_id = stdout \
        .splitlines()[0] \
        .replace("[master", "") \
        .replace("(root-commit)", "") \
        .replace("]", "") \
        .replace("test_commit", "") \
        .replace(" ", "") \
        .replace("\n", "")
    print("CommitID: <{}>".format(commit_id))
    assert len(commit_id) == 7

    commit_object, _ = _run_subprocess(["git", "cat-file", "-p", commit_id])

    return commit_id, commit_object


def verify_git_commit():
    commit_id, stdout = _commit_with_new_identity()
    signed = False
    signature: str = ""
    author = ""
    committer = ""
    keyid_from_signature = "INVALID"
    for line in stdout.splitlines():
        if line.startswith("author "):
            author = line
        if line.startswith("committer "):
            committer = line
        if line.startswith("gpgsig "):
            signed = True
            signature = line[7:] + "\n"
        if line.startswith(" -----END PGP SIGNATURE-----"):
            signature += line[1:] + "\n"
            break
        if line.startswith(" "):
            signature += line[1:] + "\n"
    assert signed
    process = subprocess.Popen(["gpg", "--list-packets"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    stdout, _ = process.communicate(signature)
    for line in stdout.splitlines():
        print("SIGNATURE_OUTPUT:", line)
        if line.startswith(":signature packet:"):
            keyid_marker = "keyid "
            keyid_from_signature = line[line.find(keyid_marker) + len(keyid_marker):16]
    _assert_string_contains_all(author, ["ANON", "@git-anon", keyid_from_signature])
    _assert_string_contains_all(committer, ["ANON", "@git-anon", keyid_from_signature])


def _verify_displayed_attributes(expected_attributes: List[Tuple[str, bool]], expected_strings: List[str], keyid_expected: bool):
    stdout, _ = _run_subprocess(["git", "log", "-n1", "--pretty=fuller", "--show-signature"])
    signed = False
    signature_verification_output: List[str] = []
    author = ""
    committer = ""
    keyid_from_signature = "INVALID"
    attributes: List[Tuple[str, bool]] = []
    for line in stdout.splitlines():
        print("GIT LOG OUTPUT:", line)
        if line.startswith("Author:"):
            author = line
        if line.startswith("Commit:"):
            committer = line
        if line.startswith("git-anon: "):
            signed = True
            signature_verification_output.append(line[len("git-anon: "):])
    assert signed
    for line in signature_verification_output:
        print("SIG VERIFY OUTPUT:", line)
        if line.find("using") != -1 and line.find("key") != -1:
            keyid_from_signature = line[-16:]
        if line.find("  [") != -1:
            attribute = line.replace("[trusted]", "").replace("[unknown]", "").lstrip()
            trust_notation = line[line.find("[") + 1:line.find("]") + 1 - line.find("[") + 1]
            attributes.append((attribute, trust_notation != "unknown"))
        assert line.find("WARNING") == -1
        assert line.find("No ") == -1  # No public key found.
    if keyid_expected:
        expected_strings.append(keyid_from_signature)
    _assert_string_contains_all(author, expected_strings)
    _assert_string_contains_all(committer, expected_strings)

    attributes.sort()
    for a, t in attributes:
        print(a, t)

    actual_count = len(attributes)
    expected_count = len(expected_attributes)
    assert actual_count == expected_count, "Expected {} attributes but found {}".format(expected_count, actual_count)

    for i in range(0, len(attributes)):
        assert attributes[i][0] == expected_attributes[i][0]
        assert attributes[i][1] == expected_attributes[i][1]


def verify_display_local_attributes():
    print("TEST: verify_display_local_attributes")
    commit_id, _ = _commit_with_new_identity()
    expected = [
        ("Grand Maester of the Nights Watch", True),
        ("Member of the Nights Watch", True),
        ("Samwell Tarly", True)
    ]
    _verify_displayed_attributes(expected, ["Samwell", "Tarly", "unknown-email"], False)
    print("DONE: verify_display_local_attributes")


def verify_display_foreign_attributes():
    print("TEST: verify_display_foreign_attributes")
    expected = [
        # ("Grand Maester of the Nights Watch", True),
        ("Member of the Nights Watch", True),
        ("Samwell Tarly", False)
    ]
    _verify_displayed_attributes(expected, ["ANON", "@git-anon"], True)
    print("DONE: verify_display_foreign_attributes")


def verify_certification_locally():
    pubkey = "../nights_watch.pub"
    seckey = "../nights_watch.sec"
    _run_subprocess(
        [
            "git", "anon", "cert", "gen-key",
            "--uid", "Member of the Nights Watch",
            "--output", pubkey,
            "--output-secret-key", seckey
        ]
    )
    assert os.path.isfile(pubkey)
    assert os.path.isfile(seckey)
    assert os.stat(pubkey).st_size > 0
    assert os.stat(seckey).st_size > 0
    _run_subprocess(["git", "anon", "new-identity"])
    _run_subprocess(["git", "commit", "-m", "commit with certified attribute", "--allow-empty"])


def _print_multiline_with_prefix(prefix: str, to_print: str):
    if to_print is None:
        print(prefix, "NOTHING TO PRINT")
    else:
        for line in to_print.splitlines():
            print(prefix, line, sep=": ")


def run_tests():
    _run_subprocess(["rm", "-rf", ".git"], check=False)
    random_section = str(random.randint(0, pow(10, 6)))
    workdir = os.path.join("testing", "system_test", random_section)
    os.makedirs(workdir, exist_ok=True)
    os.chdir(workdir)

    os.makedirs("remote_repo")
    subprocess.run(["git", "init", "--bare"], check=True, cwd="remote_repo")

    os.makedirs("first_repo")
    os.chdir("first_repo")
    _run_subprocess(["git", "init"], check=True)
    verify_install_executable_on_path()
    verify_command_enable()
    verify_command_config_set_enc_key()
    verify_commands_userid()
    verify_commands_identity_creation_and_setup()
    verify_git_commit()
    verify_display_local_attributes()
    verify_certification_locally()
    _run_subprocess(["git", "remote", "add", "origin", os.path.abspath("../remote_repo")], check=True)
    _run_subprocess(["git", "push", "-u", "origin", "master"], check=True)
    os.chdir("..")

    _run_subprocess(["git", "clone", "-b", "master", os.path.abspath("remote_repo"), "second_repo"], check=True)
    os.chdir("second_repo")
    _run_subprocess(["git", "branch"])
    _run_subprocess(["git", "anon", "enable"])
    _run_subprocess(["git", "anon", "config", "set-enc-key", "secret-for-testing"])
    _run_subprocess(["git", "anon", "cert",  "trust", "--input", "../nights_watch.pub"])
    verify_display_foreign_attributes()


class SystemTest(TestCase):

    @staticmethod
    def test_system():
        _run_subprocess(["python3", "setup.py", "bdist_wheel"])
        _run_subprocess(["docker", "build", "-t", "git-anon-system-test", "."])
        _run_subprocess(["docker", "run", "git-anon-system-test", "python3", "system_test.py"])


if __name__ == '__main__':
    if not os.environ.get("GIT_ANON_SYSTEM_TEST_AUTHORIZED") == "True":
        print("****************************************************************************************")
        print("* DO NOT RUN THIS ON YOUR DEV MACHINE !!                                               *")
        print("* This is designed to run in a throwaway environment and will mess with lots of files! *")
        print("* You can run them in a docker container with no volumes mounted or on a CI runner.    *")
        print("****************************************************************************************")
        exit(2)
    run_tests()
    print("All tests completed successfully!")
