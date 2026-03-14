import subprocess
import os
import shutil
import re
import secrets
from argparse import Namespace as Args
from pathlib import Path
from . import err
from . import config
from . import cache


def run(
    cmd: str | list[str],
    check: bool = True,
    capture_output: bool = False,
    encoding: str | None = "utf-8",
    cwd: Path | None = None,
    shell: bool = True,
    stdout=None,
    stdin=None,
    input: bytes | None = None,
    extra_env: dict = None,
):
    env = os.environ.copy()
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        cmd,
        shell=shell,
        check=check,
        capture_output=capture_output,
        encoding=encoding,
        cwd=cwd,
        stdout=stdout,
        stdin=stdin,
        input=input,
        env=env,
    )


def backup(file: Path):
    backup_directory = Path("_backup")
    backup_directory.mkdir(parents=True, exist_ok=True)
    backup = backup_directory / str(file).replace(os.path.sep, "-")
    shutil.copyfile(file, backup, follow_symlinks=True)


def ensure_exists(file: Path):
    if not file.exists():
        err.fatal(f"{file} does not exist")


def random_tmpdir(prefix="tmp-"):
    """
    Caller is responsible for cleaning up the directory.
    """
    token = secrets.token_hex(16)
    tmpdir = Path(f"{prefix}{token}")
    tmpdir.mkdir(exist_ok=False)
    return tmpdir


def find_recursive(pattern: str) -> list[Path]:
    regex = re.compile(pattern)
    matches = []
    for path, dirlist, filelist in os.walk("."):
        path = Path(path)
        for file in filelist:
            if regex.search(file):
                matches.append(path / file)
    return matches