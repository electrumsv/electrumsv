#!/usr/bin/env python3
import dataclasses
import os
import platform
import shutil
import subprocess
import sys

CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))

python_exe = shutil.which("python3")
if sys.platform == "win32":
    python_exe = sys.executable

if platform.system() == "Windows":
    platform_name = "win64"
elif platform.system() == "Darwin":
    platform_name = "macos"
elif platform.system() == "Linux":
    platform_name = "linux"
else:
    print(f"Unsupported platform {platform.system()}")
    sys.exit(0)

executable_name = "pip-compile"
compiler_path = None
if sys.platform == "win32":
    executable_name = "ignored-first-argument"
    python_exe = sys.executable
    python_path = os.path.dirname(sys.executable)
    scripts_path = os.path.join(python_path, "scripts")
    assert os.path.exists(scripts_path)
    compiler_path = os.path.join(scripts_path, "pip-compile.exe")
    assert os.path.exists(compiler_path)


print("Installing pip-tools")
subprocess.run([ python_exe, "-m", "pip", "install", "pip-tools" ])


@dataclasses.dataclass
class OutputFileMetadata:
    output_suffix: str
    ordered_input_filenames: list[str]
    for_platforms: set[str] = dataclasses.field(default_factory=set)

output_file_metadatas = [
    OutputFileMetadata("-electrumsv-lite", [
        "requirements.txt",
        "requirements-electrumsv.txt",
    ]),
    OutputFileMetadata("-electrumsv", [
        "requirements.txt",
        "requirements-electrumsv.txt",
        "requirements-hw.txt",
    ]),
    OutputFileMetadata("-payd", [
        "requirements.txt",
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
    ], { "win64" }),
]

for metadata in output_file_metadatas:
    if metadata.for_platforms and platform_name not in metadata.for_platforms:
        continue

    input_paths = [ os.path.join(CONTRIB_PATH, "requirements", input_filename)
        for input_filename in metadata.ordered_input_filenames ]
    output_path = os.path.join(CONTRIB_PATH, "deterministic-build",
        f"{platform_name}-py3.10-requirements{metadata.output_suffix}.txt")

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
