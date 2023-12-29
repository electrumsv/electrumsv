#!/usr/bin/env python3
import dataclasses
import os
import platform
import shutil
import subprocess
import sys
from typing import List, Set

CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))
PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}"

python_exe = shutil.which("python3")

if platform.system() == "Windows":
    python_exe = sys.executable
    if platform.architecture()[0] == "32bit":
        platform_name = "win32"
    elif platform.architecture()[0] == "64bit":
        platform_name = "win64"
    else:
        sys.exit(f"Unknown Windows architecture {platform.architecture()}")
elif platform.system() == "Darwin":
    platform_name = "macos"
elif platform.system() == "Linux":
    platform_name = "linux"
else:
    print(f"Unsupported platform {platform.system()}")
    sys.exit(0)

executable_name = "pip-compile"
if sys.platform == "win32":
    executable_name = "ignored-first-argument"
    python_exe = sys.executable

print("Installing pip-tools")
subprocess.run([ python_exe, "-m", "pip", "install", "pip-tools" ])

compiler_path = None
if sys.platform == "win32":
    python_path = os.path.dirname(sys.executable)
    if python_path.lower().endswith(r"\scripts"): # pipenv environment.
        scripts_path = python_path
    else: # likely normal looking Python install environment.
        scripts_path = os.path.join(python_path, "scripts")
        assert os.path.exists(scripts_path), f"'{scripts_path}' not found"
    compiler_path = os.path.join(scripts_path, "pip-compile.exe")
    assert os.path.exists(compiler_path)


@dataclasses.dataclass
class OutputFileMetadata:
    output_suffix: str
    ordered_input_filenames: List[str]
    for_platforms: Set[str] = dataclasses.field(default_factory=set)

output_file_metadatas = [
    OutputFileMetadata("-electrumsv", [
        "requirements.txt",
        "requirements-electrumsv.txt",
        "requirements-hw.txt",
    ]),
    OutputFileMetadata("-dev", [
        "requirements.txt",
        "requirements-electrumsv.txt",
        "requirements-hw.txt",
        "requirements-dev.txt",
    ]),
    OutputFileMetadata("-pyinstaller", [
        "requirements-pyinstaller.txt"
    ], { "win64", "win32" }),
]

for metadata in output_file_metadatas:
    if metadata.for_platforms and platform_name not in metadata.for_platforms:
        continue

    input_paths = [ os.path.join(CONTRIB_PATH, "requirements", input_filename)
        for input_filename in metadata.ordered_input_filenames ]
    output_path = os.path.join(CONTRIB_PATH, "deterministic-build",
        f"{platform_name}-py{PYTHON_VERSION}-requirements{metadata.output_suffix}.txt")

    # Quote from documentation of pip-tools:
    # In future versions, the ``--allow-unsafe`` behavior will be used by default
    # and the option will be removed. It is recommended to pass the argument now to
    # adapt projects to the upcoming change.
    command_args = [ executable_name, "--allow-unsafe", "--generate-hashes", "--no-reuse-hashes", f"--output-file={output_path}" ]
    command_args.extend(input_paths)
    ret = subprocess.check_call(command_args, executable=compiler_path)
    if ret != 0:
        print("Failed running command")
        sys.exit(ret.returncode)
    print("OK.")

print("Done. Updated requirements")
