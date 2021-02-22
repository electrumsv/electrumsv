#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys

CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))

python_exe = shutil.which("python3")
if sys.platform == "win32":
    python_exe = sys.executable

print(f"Installing pip-tools")
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
    # The only affected dependency for ElectrumSV is setuptools which we pin to 51.0.0 currently
    subprocess.check_call(f"pip-compile --allow-unsafe --generate-hashes --output-file={dr_path}"
                          f" {r_path}")
    print("OK.")

print("Done. Updated requirements")
