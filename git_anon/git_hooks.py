from git_anon.git_config import GitConfig


POST_MERGE_HOOK = """#!/bin/bash
exec git-anon update-mappings
"""  # todo this hook should use the api directly and not rely on the cli

POST_COMMIT_HOOK = """#!/bin/bash
exec git-anon new-identity
"""  # todo this hook should use the api directly and not rely on the cli


class HooksManager:
    git_config: GitConfig

    def __init__(self, git_config: GitConfig):
        self.git_config = git_config

    def enable(self) -> None:
        self.git_config.set_hook("post-merge", self._create_hook(POST_MERGE_HOOK))
        self.git_config.set_hook("post-commit", self._create_hook(POST_COMMIT_HOOK))

    def disable(self) -> None:
        self.git_config.remove_hook("post-merge")
        self.git_config.remove_hook("post-commit")

    @staticmethod
    def _create_hook(source: str) -> bytes:
        return bytes(source, 'utf-8')
