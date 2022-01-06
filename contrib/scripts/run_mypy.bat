@echo off
@rem "to specify default python version to 3.9 create/edit ~/AppData/Local/py.ini with [default] set
@rem to python3=3.9"

REM Get current folder with no trailing slash
SET ScriptDir=%~dp0
SET TLD=%ScriptDir%\..\..
echo %ScriptDir%
cd %ScriptDir%

py -m pip install types-certifi types-pkg_resources types-python-dateutil types-requests
py -m pip install git+https://github.com/python-qt-tools/PyQt5-stubs.git@166af25fbe0886f95ef0b1a1b57bbdc893e9144d
py -m mypy --install-types --non-interactive
py -m mypy --config=%TLD%\mypy.ini %TLD%\electrumsv  --python-version 3.10
