# TODO: Add the missing QR code dependencies.
# TODO: Verify the Python source archive GPG signature.
#       - It might actually be better to do download and verification as a developer who is
#         priming the initial (hopefully) reproducible build. Then the hashes can help ensure
#         that the content does not change, and can be embedded in github for the reproducibility.
# TODO: The whole point of specifying what pip, setuptools and wheel versions to use when
#       bootstrapping pip, is to make sure they match the versions in the deterministic
#       requirements.
# TODO:

#
# Git commits of interest:
#
# Where the Python embedded build would run with ElectrumSV installed into it.
# https://github.com/electrumsv/electrumsv/blob/a4f6da0a7778553acf89a6fae669abfd11d32388/contrib/build-windows/run.py

import hashlib
import logging
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tarfile
import threading
from typing import TextIO, Optional, Sequence, Tuple
import zipfile

import requests


SCRIPT_PATH = pathlib.Path(os.path.realpath(__file__))
BASE_PATH = SCRIPT_PATH.parent
REQUIREMENTS_PATH = BASE_PATH.parent / "deterministic-build"
SOURCE_PATH = BASE_PATH.parent.parent
SOURCE_SNAPSHOT_URL = "https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"
SOURCE_ARCHIVE_FILENAME = "Python-{version}.tar.xz"
PYINSTALLER_SPEC_NAME = "electrum-sv.spec"
LIBUSB_DLL_NAME = "libusb-1.0.dll"
LIBZBAR_DLL_NAME = "libzbar-0.dll"

HASH_CHUNK_SIZE = 65536

PYTHON_VERSION = "3.7.9"
PYTHON_ARCH = "win32" # amd64
PYTHON_ABI = "cp37"

BUILD_ARCH = {
    "amd64": "x64",
    "win32": "win32",
}

VS_ARCH = {
    "amd64": "x64",
    "win32": "x86",
}

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

logger = _initialise_logging("build-windows")

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


def _run_command(*args: Sequence[str], cwd: Optional[pathlib.Path]=None,
        preserve_env: bool=True) -> None:
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

    env = None if preserve_env else { 'SYSTEMROOT': os.environ['SYSTEMROOT'], 'PATH': '.' }
    process = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE,
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

def _build_libusb(download_path: pathlib.Path, output_path: pathlib.Path, build_arch: str) \
        -> pathlib.Path:
    """ Returns path to compiled DLL or raises exception. """
    source_archive_filename = "eee6998395184d87bd8e9c07ce2637caed1207f4.zip"
    download_url = ("https://github.com/libusb/libusb/archive/"
        "eee6998395184d87bd8e9c07ce2637caed1207f4.zip")
    _download_file(download_url, download_path / source_archive_filename)

    # The zip file has an internal folder that differs from the archive name.
    build_path = output_path / "libusb-eee6998395184d87bd8e9c07ce2637caed1207f4"
    if not build_path.exists():
        logger.info(f"Extracting {source_archive_filename}")
        with zipfile.ZipFile(download_path / source_archive_filename) as z:
            z.extractall(output_path)

    _run_command("msbuild.exe", os.path.join("msvc", "libusb_dll_2019.vcxproj"),
        "/p:Configuration=Release", f"/p:Platform={build_arch}",
        cwd=build_path)

    dll_path = build_path / build_arch / "Release" / "dll" / LIBUSB_DLL_NAME
    assert dll_path.exists(), "The libusb dll did not appear to get built"
    return dll_path

def build_for_platform(python_arch: str, python_version: str, python_abi: str) -> None:
    # Where to store the downloaded files.
    download_path = BASE_PATH / "downloads"
    download_path.mkdir(exist_ok=True, parents=True)

    # Where to produce build artifacts / working data.
    output_path = BASE_PATH / python_arch
    output_path.mkdir(exist_ok=True, parents=True)

    build_path = output_path / f"Python-{python_version}"
    if build_path.exists():
        shutil.rmtree(build_path)

    # Download the libusb source code and compile it for the build platform.
    build_arch = BUILD_ARCH[python_arch]
    libusb_dll_path = _build_libusb(download_path, output_path, build_arch)

    # Download the Python source code.
    download_url = SOURCE_SNAPSHOT_URL.format(version=python_version)
    source_archive_filename = SOURCE_ARCHIVE_FILENAME.format(version=python_version)
    _download_file(download_url, download_path / source_archive_filename)

    # The Python source code does not include pip support. We need the bootstrap script.
    getpip_script_path = download_path / "get-pip.py"
    _download_file("https://bootstrap.pypa.io/get-pip.py", getpip_script_path)

    # Extract and build the Python source code.
    logger.info(f"Extracting {source_archive_filename}")
    with tarfile.open(download_path / source_archive_filename, 'r') as z:
        def is_within_directory(directory, target):
            
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
        
            prefix = os.path.commonprefix([abs_directory, abs_target])
            
            return prefix == abs_directory
        
        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        
            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")
        
            tar.extractall(path, members, numeric_owner=numeric_owner) 
            
        
        safe_extract(z, output_path)

    _run_command(str(build_path / "PCbuild" / "build.bat"), "-e", "--no-tkinter",
        "-p", build_arch)

    executable_path = build_path / "PCbuild" / build_arch / "python.exe"
    assert executable_path.exists(), "failed to build the python interpreter"

    # Ensure that the libusb DLL is in the right place for PyInstaller to find (via the spec file).
    shutil.copyfile(libusb_dll_path, build_path / LIBUSB_DLL_NAME)

    zbar_dll_path = BASE_PATH / "prebuilt" / LIBZBAR_DLL_NAME
    shutil.copyfile(zbar_dll_path, build_path / LIBZBAR_DLL_NAME)

    # Ensure the PyInstaller spec file in in the right place for us to execute later.
    pyinstaller_spec_path = BASE_PATH / PYINSTALLER_SPEC_NAME
    shutil.copyfile(pyinstaller_spec_path, build_path / PYINSTALLER_SPEC_NAME)

    # These versions should be aligned with the existing deterministic requirements.
    _run_command(str(executable_path),
        str(getpip_script_path),
        "--no-warn-script-location", "pip==20.2.3", "setuptools==50.3.0", "wheel==0.35.1",
        cwd=build_path, preserve_env=False)

    for ext_text in ("", "-binaries", "-hw", "-pyinstaller"):
        _run_command(str(executable_path), "-m", "pip", "-v", "install",
            "-r", str(REQUIREMENTS_PATH / f"requirements{ext_text}.txt"),
            "--no-warn-script-location",
            cwd=build_path, preserve_env=False)

    _run_command(str(executable_path), "-m", "pip", "-v", "install", ".",
        "--no-warn-script-location",
        cwd=SOURCE_PATH, preserve_env=False)

    _run_command(str(executable_path), "-m", "PyInstaller", PYINSTALLER_SPEC_NAME,
        cwd=build_path, preserve_env=False)

def run(python_arch: str, python_version: str) -> None:
    vs_arch = VS_ARCH[python_arch]
    vs_target_arch = os.environ.get("VSCMD_ARG_TGT_ARCH", None)
    if vs_target_arch is None:
        sys.exit(f"Please run native tools command prompt for {vs_arch}")
    if vs_target_arch != vs_arch:
        sys.exit(f"Please run native tools command prompt for {vs_arch}, "
            f"you are currently in the native tools command prompt for {vs_target_arch}")
    build_for_platform(python_arch, python_version, PYTHON_ABI)


if __name__ == "__main__":
    run(PYTHON_ARCH, PYTHON_VERSION)
