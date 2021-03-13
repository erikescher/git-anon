import subprocess
from typing import Mapping, List


def run_subprocess_and_return_stdout_as_bytes(args: List[str], check_return_code: bool = True,
                                              workdir: str = None) -> bytes:
    process = subprocess.run(
        args,
        check=check_return_code,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=workdir
    )
    return process.stdout


def run_subprocess_and_return_stdout_as_str(args: List[str], check_return_code: bool = True, workdir: str = None,
                                            env: Mapping[str, str] = None) -> str:
    process = subprocess.run(
        args,
        check=check_return_code,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
        cwd=workdir,
        env=env
    )
    return process.stdout
