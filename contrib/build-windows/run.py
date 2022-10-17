# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# TODO: Add the missing QR code dependencies.
# TODO: Verify the Python source archive GPG signature.
#       - It might actually be better to do download and verification as a developer who is
#         priming the initial (hopefully) reproducible build. Then the hashes can help ensure
#         that the content does not change, and can be embedded in github for the reproducibility.
# TODO: Do we want to replace requirements-pyinstaller with just installing pyinstaller, as we
#       now have to do.
# NOTE: The whole point of specifying what pip, setuptools and wheel versions to use when
#       bootstrapping pip, is to make sure they match the versions in the deterministic
#       requirements.

# NOTE: For the PyInstaller build artifact, look for the `Python-3.7.9\dist\electrumsv` directory.
# NOTE: To run ElectrumSV as installed in the embedded Python, enter the `Python-3.7.9` directory
#

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
ZBAR_DLL_PATH = BASE_PATH / "prebuilt" / LIBZBAR_DLL_NAME

HASH_CHUNK_SIZE = 65536

PYTHON_VERSION = "3.10.7"
PYTHON_ARCH = "amd64"
PYTHON_ABI = "cp310"

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

    if preserve_env:
        env = None
    else:
        env = os.environ.copy()
        filtered_paths = [ line for line in env["PATH"].split(";") if "python" not in line.lower() ]
        env["PATH"] = ";".join(filtered_paths)
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


def install_electrumsv(executable_path: pathlib.Path, build_path: pathlib.Path) -> None:
    # Install all ElectrumSV's deterministic dependencies into the build's site-packages.
    for ext_text in ("", "-binaries", "-hw"):
        _run_command(str(executable_path), "-m", "pip", "-v", "install",
            "-r", str(REQUIREMENTS_PATH / f"requirements{ext_text}.txt"),
            "--no-warn-script-location",
            cwd=build_path, preserve_env=False)

    # Install ElectrumSV into the build's site-packages.
    _run_command(str(executable_path), "-m", "pip", "-v", "install", ".",
        "--no-warn-script-location",
        cwd=SOURCE_PATH, preserve_env=False)


def run_pyinstaller(executable_path: pathlib.Path, build_path: pathlib.Path,
        output_path: pathlib.Path) -> None:
    _run_command(str(executable_path), "-m", "pip", "install", "pyinstaller",
        "--no-warn-script-location",
        cwd=build_path, preserve_env=False)

    # Ensure the PyInstaller spec file in in the right place for us to execute.
    pyinstaller_spec_path = BASE_PATH / PYINSTALLER_SPEC_NAME
    shutil.copyfile(pyinstaller_spec_path, build_path / PYINSTALLER_SPEC_NAME)

    _run_command(str(executable_path), "-m", "PyInstaller", PYINSTALLER_SPEC_NAME,
        "--workpath", str(output_path / "build-pyinstaller"),
        "--distpath", str(output_path / "dist-pyinstaller"),
        cwd=build_path, preserve_env=False)

    _run_command(str(executable_path), "-m", "pip", "uninstall", "-y", "pyinstaller", "pip",
        cwd=build_path, preserve_env=False)


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
    logger.info("Extracting %s", source_archive_filename)
    with tarfile.open(download_path / source_archive_filename, 'r') as z:
        z.extractall(output_path)

    _run_command(str(build_path / "PCbuild" / "build.bat"), "-e", "--no-tkinter",
        "-p", build_arch)

    executable_path = build_path / "PCbuild" / python_arch / "python.exe"
    logger.info("expected executable path: %s", executable_path)
    assert executable_path.exists(), "failed to build the python interpreter"

    embedded_dist_path = output_path / "dist-embedded"

    # Create the embedded distribution before we add the dependencies so that the standard library
    # is all that is in the embedded build's source zip archive.
    # ```
    # python.bat PC\layout -s . -t ..\build-embedded --copy ..\dist-embedded --precompile
    #   --zip-lib --include-underpth --include-stable --flat-dlls
    # ```
    _run_command(str(executable_path), r"PC\layout",
        "-s", str(build_path),
        "-t", str(output_path / "build-embedded"),
        "--copy", str(embedded_dist_path),
        "--precompile", "--zip-lib", "--include-underpth", "--include-stable", "--flat-dlls",
        cwd=build_path, preserve_env=False)

    # Ensure that the extra DLLs are in the right place for PyInstaller to find (via the spec file).
    shutil.copyfile(libusb_dll_path, build_path / LIBUSB_DLL_NAME)
    shutil.copyfile(ZBAR_DLL_PATH, build_path / LIBZBAR_DLL_NAME)

    # Ensure that the extra DLLs are in the embedded build.
    shutil.copyfile(libusb_dll_path, embedded_dist_path / LIBUSB_DLL_NAME)
    shutil.copyfile(ZBAR_DLL_PATH, embedded_dist_path / LIBZBAR_DLL_NAME)

    # These versions should be aligned with the existing deterministic requirements.
    _run_command(str(executable_path),
        str(getpip_script_path),
        "--no-warn-script-location", "pip==21.2.4", "setuptools==58.0.3", "wheel==0.36.1",
        cwd=build_path, preserve_env=False)

    install_electrumsv(executable_path, build_path)
    run_pyinstaller(executable_path, build_path, output_path)

    # TODO: The following only apply if the embedded build
    # TODO: Copy the site-packages to the embedded build?
    # TODO: Pre-compile the scripts in site-packages.
    # TODO: Update `python39.pth` in the embedded build directory.


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
