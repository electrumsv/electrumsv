import hashlib
import logging
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import threading
from typing import TextIO, Optional, Sequence, Tuple
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
PYTHON_ARCH = "win32" # amd64
PYTHON_ABI = "cp37"

WINDOWS_PLATFORM = {
    "win32": "win32",
    "amd64": "win_amd64",
}


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
    def get_lines(fd: TextIO, local_queue: queue.Queue) -> None:
        for line in iter(fd.readline, ''):
            local_queue.put(line)
        local_queue.put(None)

    def create_reader_thread(fd: TextIO) -> Tuple[queue.Queue, threading.Thread]:
        local_queue = queue.Queue()
        thread = threading.Thread(target=get_lines, args=(fd, local_queue))
        thread.daemon = True
        thread.start()
        return local_queue, thread

    process = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, universal_newlines=True)

    debug_queue, stdout_thread = create_reader_thread(process.stdout)
    error_queue, stderr_thread = create_reader_thread(process.stderr)

    errored = False
    while stdout_thread.is_alive() or stderr_thread.is_alive():
        for line in iter(debug_queue.get, None):
            logger.debug(line.rstrip())
        for line in iter(error_queue.get, None):
            errored = errored or "ERROR:" in line
            logger.error(line.rstrip())

    if errored:
        raise Exception("Process errored")


def run(python_arch: str, python_version: str, python_abi: str) -> None:
    base_output_path = BASE_PATH / "output"
    output_path = base_output_path / python_arch / python_version
    output_path.mkdir(exist_ok=True, parents=True)

    build_path = output_path / "build"
    if build_path.exists():
        shutil.rmtree(build_path)
    build_path.mkdir(exist_ok=False)
    (build_path / "DLLs").mkdir(exist_ok=False)

    # venv_path = output_path / "venv"

    # We start off with the embeddable release of Python, which is provided for both win32 and
    # amd64. https://docs.python.org/3.7/using/windows.html#the-embeddable-package
    embed_url = EMBED_URL.format(arch=python_arch, version=python_version)
    embed_filename = EMBED_FILENAME.format(arch=python_arch, version=python_version)
    _download_file(embed_url, output_path / embed_filename)

    logger.info(f"Extracting {embed_filename}")
    with zipfile.ZipFile(output_path / embed_filename, 'r') as z:
        z.extractall(build_path)

    _download_file("https://bootstrap.pypa.io/get-pip.py", base_output_path / "get-pip.py")

    shutil.copyfile(build_path / "python37._pth", build_path / "python37.pth.orig")
    with open(build_path / "python37._pth", "r") as f:
        text = f.read()
    with open(build_path / "python37._pth", "w") as f:
        f.write("Lib" + os.linesep)
        f.write(text.replace("#import site", "import site"))

    lib_path = build_path / "Lib"
    lib_path.mkdir()

    for ext_text in ("", "-binaries", "-hw"):
        _run_command(sys.executable, "-m", "pip", "-v", "install",
            "--target", str(lib_path),
            "--no-deps",
            "--platform", WINDOWS_PLATFORM[python_arch],
            "--python-version", python_version,
            "--implementation", "cp",
            "--abi", python_abi,
            "-r", str(REQUIREMENTS_PATH / f"requirements{ext_text}.txt"),
            "--no-warn-script-location",
            cwd=build_path)

    _run_command(sys.executable, "-m", "pip", "-v", "install",
        "--target", str(lib_path),
        "--no-deps",
        "--platform", WINDOWS_PLATFORM[python_arch],
        "--python-version", python_version,
        "--implementation", "cp",
        "--abi", python_abi,
        ".",
        "--no-warn-script-location",
        cwd=SOURCE_PATH)

    # _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", ".",
    #     "--no-warn-script-location", cwd=SOURCE_PATH)

    # _run_command(str(build_path / "Scripts" / "pip3.exe"), "install", "pyinstaller",
    #     "--no-warn-script-location", cwd=SOURCE_PATH)


logger = _initialise_logging("build-windows")
run(PYTHON_ARCH, PYTHON_VERSION, PYTHON_ABI)
