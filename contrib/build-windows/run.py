import hashlib
import logging
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional, Sequence
import zipfile

import requests


# TODO: Fix ._pth hard-coded version.
# TODO: Verify the Python.org gpg signatures.
#       - It might actually be better to do download and verification as a developer who is
#         priming the initial (hopefully) reproducible build. Then the hashes can help ensure
#         that the content does not change, and can be embedded in github for the reproducibility.


SCRIPT_PATH = pathlib.Path(os.path.realpath(__file__))
BASE_PATH = SCRIPT_PATH.parent
REQUIREMENTS_PATH = BASE_PATH.parent / "deterministic-build"
SOURCE_PATH = BASE_PATH.parent.parent
EMBED_URL = "https://www.python.org/ftp/python/{version}/python-{version}-embed-{arch}.zip"
EMBED_FILENAME = "python-{version}-embed-{arch}.zip"

HASH_CHUNK_SIZE = 65536

PYTHON_VERSION = "3.7.9"
PYTHON_ARCH = "win32"


assert (REQUIREMENTS_PATH / "requirements.txt").exists(), f"{REQUIREMENTS_PATH} does not exist"


def _initialise_logging(context_name: str) -> logging.Logger:
    logger = logging.getLogger(context_name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    return logger


def _sha256hash_file(file_path: pathlib.Path) -> str:
    hasher = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(HASH_CHUNK_SIZE)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()


def _download_file(url: str, output_path: pathlib.Path) -> None:
    if not output_path.exists():
        logger.info(f"Downloading '{output_path.name}'")
        # Requests verifies SSL certificates.
        assert url.startswith("https"), f"'{url}' must be HTTPS"
        r = requests.get(url)
        with open(output_path, "wb") as f:
            f.write(r.content)

    file_hash = _sha256hash_file(output_path)
    logger.info(f"sha256 {output_path.name}: {file_hash}")


def _run_command(*args: Sequence[str], cwd: Optional[pathlib.Path]=None) -> None:
    env = {}
    env['SYSTEMROOT'] = os.environ['SYSTEMROOT']
    p = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    text = p.stdout.readline()
    while text:
        logger.debug(text.decode())
        text = p.stdout.readline()


def run(arch: str, python_version: str) -> None:
    base_output_path = BASE_PATH / "output"
    output_path = base_output_path / arch / python_version
    output_path.mkdir(exist_ok=True, parents=True)

    build_path = output_path / "build"
    if build_path.exists():
        shutil.rmtree(build_path)
    build_path.mkdir(exist_ok=False)
    (build_path / "DLLs").mkdir(exist_ok=False)

    # venv_path = output_path / "venv"

    # We start off with the embeddable release of Python, which is provided for both win32 and
    # amd64. https://docs.python.org/3.7/using/windows.html#the-embeddable-package
    embed_url = EMBED_URL.format(arch=PYTHON_ARCH, version=PYTHON_VERSION)
    embed_filename = EMBED_FILENAME.format(arch=PYTHON_ARCH, version=PYTHON_VERSION)
    _download_file(embed_url, output_path / embed_filename)

    logger.info(f"Extracting {embed_filename}")
    with zipfile.ZipFile(output_path / embed_filename, 'r') as z:
        z.extractall(build_path)

    _download_file("https://bootstrap.pypa.io/get-pip.py", base_output_path / "get-pip.py")

    shutil.copyfile(build_path / "python37._pth", build_path / "python37.pth.orig")
    with open(build_path / "python37._pth", "r") as f:
        text = f.read()
    with open(build_path / "python37._pth", "w") as f:
        f.write(text.replace("#import site", "import site"))

    # We align pip, setuptools and wheel in order to prevent pip-related errors.
    _run_command(str(build_path / "python.exe"), str(base_output_path / "get-pip.py"),
        "--no-warn-script-location", "pip==20.2.2", "setuptools==49.6.0",
        "wheel==0.35.1", cwd=build_path)

    _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", "virtualenv",
        "--no-warn-script-location", cwd=build_path)

    # _run_command(str(build_path / "Scripts" / "virtualenv.exe"), str(venv_path), cwd=build_path)

    # assert venv_path.exists()

    for ext_text in ("", "-binaries", "-hw"):
        _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", "-r",
            str(REQUIREMENTS_PATH / f"requirements{ext_text}.txt"), "--no-warn-script-location",
            cwd=build_path)

    _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", ".",
        "--no-warn-script-location", cwd=SOURCE_PATH)

    _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", "pyinstaller",
        "--no-warn-script-location", cwd=SOURCE_PATH)


logger = _initialise_logging("build-windows")
run(PYTHON_ARCH, PYTHON_VERSION)
