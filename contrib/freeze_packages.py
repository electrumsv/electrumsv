#!/usr/bin/env python3
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

# NOTE(rt12) 2023-01-30 The latest version of Setuptools is 67.0.0 and it
#     errors rejecting the (unused) `extras_require` section of the
#     `btchip-python` dependency. This section is parsed correctly in 65.5.0.
subprocess.run([ python_exe, "-m", "pip", "install", "setuptools==65.5.0" ])

print("Installing pip-tools")
subprocess.run([ python_exe, "-m", "pip", "install", "pip-tools" ])

for r_suffix in [ '-pyinstaller', '',  '-hw' ]:
    requirements_filename = f"requirements{r_suffix}.txt"
    r_path = os.path.join(CONTRIB_PATH, "requirements", requirements_filename)
    dr_path = os.path.join(CONTRIB_PATH, "deterministic-build",
        f"{platform_name}-py3.10-requirements{r_suffix}.txt")

    """  Quote from documentation of pip-tools:
    In future versions, the ``--allow-unsafe`` behavior will be used by default
    and the option will be removed. It is recommended to pass the argument now to
    adapt projects to the upcoming change.
    """
    # The only affected dependency for ElectrumSV is setuptools which we pin to 51.0.0 currently
    command_args = [ executable_name, "--allow-unsafe", "--generate-hashes", f"--output-file={dr_path}", r_path ]
    ret = subprocess.check_call(command_args, executable=compiler_path)
    if ret != 0:
        print("Failed running command")
        sys.exit(ret.returncode)
    print("OK.")

print("Done. Updated requirements")
