#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys

venv_dir = os.path.join(os.path.expanduser('~'), ".electrum-sv-venv")
CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))

if shutil.which("virtualenv") is None:
    print("Please install virtualenv", file=sys.stderr)
    sys.exit(1)

if sys.platform == "win32":
    venv_script_dirname = "Scripts"
else:
    venv_script_dirname = "bin"

python_exe = shutil.which("python3")
if sys.platform == "win32":
    python_exe = sys.executable

for r_suffix in [ '',  '-hw', '-binaries']:
    if os.path.exists(venv_dir):
        shutil.rmtree(venv_dir)

    print(f"virtualenv -p \"{sys.executable}\" {venv_dir}")
    os.system(f"virtualenv -p \"{sys.executable}\" {venv_dir}")

    venv_python = os.path.join(venv_dir, venv_script_dirname, "python")
    venv_pip = os.path.join(venv_dir, venv_script_dirname, "pip")

    requirements_filename = f"requirements{r_suffix}.txt"
    print(f"Installing dependencies for '{requirements_filename}'")

    r_path = os.path.join(CONTRIB_PATH, "requirements", requirements_filename)
    result = subprocess.run([ venv_pip, "install", "-r", r_path, "--upgrade" ])

    result = subprocess.run([ venv_pip, 'freeze', '--all'], stdout=subprocess.PIPE)
    package_names = result.stdout.splitlines()

    print("OK.")

    print("Generating package hashes...")
    subprocess.run([ venv_pip, "install", "hashin" ])

    dr_path = os.path.join(CONTRIB_PATH, "deterministic-build", f"requirements{r_suffix}.txt")
    # If these files are not updating correctly, they can be forced to update by deleting them.
    # But hashin will not write to a non-existent requrirements file, so we should recreate them.
    if not os.path.exists(dr_path):
        with open(dr_path, 'w') as f:
            f.write('')

    print(f".. target: {dr_path}")
    for package_name in package_names:
        print(f".. hashing {package_name}")
        subprocess.run(
            [ venv_python, "-m", "hashin", "-r", dr_path, bytes.decode(package_name, 'utf-8') ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

    print("OK.")

print("Done. Updated requirements")
