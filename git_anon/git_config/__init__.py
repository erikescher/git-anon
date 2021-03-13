import os
from typing import Union

from git import GitConfigParser
from git import Repo

from git_anon.system_interactions.subprocess_utils import run_subprocess_and_return_stdout_as_bytes


class GitConfig:
    repo: Repo
    path: str

    def __init__(self, repo: Repo = None, path: str = None):
        if repo is None and path is None:
            raise SyntaxError("Must provide either path or repo.")
        if repo is not None and path is not None:
            raise SyntaxError("Only provide either path or repo.")
        if repo is not None:
            if not isinstance(repo, Repo):
                raise SyntaxError("Repo must be of type git.Repo")
            self.repo = repo
            self.path = self.repo.working_dir
        if path is not None:
            self.repo = Repo(path)
            self.path = path

    def _get_config_writer(self) -> GitConfigParser:
        return self.repo.config_writer("repository")

    def _get_config_reader(self):
        return self.repo.config_reader("repository")

    def set_user_identity(self, name: str, email: str, signing_key_identifier: str = None) -> None:
        self.set_value("user", "name", name)
        self.set_value("user", "email", email)

        if signing_key_identifier is not None and not False:
            self.set_value("user", "signingkey", signing_key_identifier)
            self.set_value("commit", "gpgsign", True)
            self.set_value("tag", "gpgsign", True)
        else:
            self.unset_signing_key()

    def unset_signing_key(self):
        self.unset_value("user", "signingkey")
        self.unset_value("commit", "gpgsign")
        self.unset_value("tag", "gpgsign")

    def unset_user_identity(self):
        self.unset_value("user", "name")
        self.unset_value("user", "email")
        self.unset_signing_key()

    def unset_value(self, section: str, option: str):
        key = section + "." + option
        workdir = os.getcwd()
        os.chdir(self.path)
        run_subprocess_and_return_stdout_as_bytes(["git", "config", "--unset", key], check_return_code=False)
        os.chdir(workdir)

    def set_gpg_program(self, command: str) -> None:
        self.set_value("gpg", "program", command)

    def unset_gpg_program(self) -> None:
        self.unset_value("gpg", "program")

    def set_gpg_home(self) -> None:
        self.set_gpg_program("helper-for-git-anon")

    def unset_gpg_home(self):
        self.unset_gpg_program()
        gpg_wrapper_path = os.path.join(self.repo.git_dir, "gpg-wrapper.sh")
        os.remove(gpg_wrapper_path)

    def set_value(self, section: str, option: str, value: Union[str, bool]) -> None:
        with self._get_config_writer() as config_writer:
            config_writer.set_value(section, option, value)

    def get_value(self, section: str, option: str):
        with self._get_config_reader() as config_reader:
            config_reader.get_value(section, option)

    @property
    def mailmap_file_path(self):
        return os.path.abspath(os.path.join(self.repo.git_dir, "git-anon", "mailmap"))

    def enable_mailmap(self):
        self.set_value("mailmap", "file", self.mailmap_file_path)

    def set_hook(self, trigger: str, executable_file_content: bytes) -> None:
        # Interesting Hooks:
        #  update, post-commit, pre-commit, pre-push, ...
        hooks_file = self._get_hook_path(trigger)
        with open(hooks_file, "wb") as file:
            file.write(executable_file_content)
        os.chmod(hooks_file, 0o700)

    def remove_hook(self, trigger: str) -> None:
        hooks_file = self._get_hook_path(trigger)
        if os.path.isfile(hooks_file):
            os.remove(hooks_file)

    def _get_hook_path(self, trigger: str) -> str:
        hooks_dir = os.path.join(self.repo.git_dir, 'hooks')
        os.makedirs(hooks_dir, exist_ok=True)
        hooks_file = os.path.join(hooks_dir, trigger)
        return hooks_file
