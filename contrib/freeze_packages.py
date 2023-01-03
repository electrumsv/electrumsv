#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys

CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))

python_exe = shutil.which("python3")
# TODO: Work out where this script is on non-windows platforms.
compiler_path = None
if sys.platform == "win32":
    python_exe = sys.executable
    python_path = os.path.dirname(sys.executable)
    scripts_path = os.path.join(python_path, "scripts")
    assert os.path.exists(scripts_path)
    compiler_path = os.path.join(scripts_path, "pip-compile.exe")
    assert os.path.exists(compiler_path)

print("Installing pip-tools")
subprocess.run([ python_exe, "-m", "pip", "install", "pip-tools" ])

for r_suffix in [ '-pyinstaller', '',  '-hw', '-binaries' ]:
    requirements_filename = f"requirements{r_suffix}.txt"
    r_path = os.path.join(CONTRIB_PATH, "requirements", requirements_filename)
    dr_path = os.path.join(CONTRIB_PATH, "deterministic-build", f"requirements{r_suffix}.txt")

    """  Quote from documentation of pip-tools:
    In future versions, the ``--allow-unsafe`` behavior will be used by default
    and the option will be removed. It is recommended to pass the argument now to
    adapt projects to the upcoming change.
    """
    # The only affected dependency for ElectrumSV is setuptools which we pin.
    # Note that we pass the executable path for `pip-compile` for the version of Python that
    # we are using, not the version for the default Python install. This strips the first value
    # in the parameter list as an ignored executable name (we put `"whateverz"` here to illustrate
    # this is not used.
    subprocess.check_call("whateverz --allow-unsafe --generate-hashes "
        f"--output-file={dr_path} {r_path}", executable=compiler_path)
    print("OK.")

print("Done. Updated requirements")
