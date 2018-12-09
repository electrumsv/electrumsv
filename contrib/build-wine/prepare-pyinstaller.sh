#!/bin/bash
source `dirname "$0"`/vars.sh
if [[ -z "${WINEPREFIX}" ]]; then
	echo Failed to import variables.
	exit 0
fi

#PYINSTALLER_GIT_URL=https://github.com/Electrum-SV/pyinstaller
PYINSTALLER_GIT_URL=https://github.com/rt121212121/pyinstaller
BRANCH=fix_2952

PYHOME=c:/python$PYTHON_VERSION
PYTHON="wine $PYHOME/python.exe -OO -B"

cd `dirname $0`
set -e
cd tmp
if [ ! -d "pyinstaller" ]; then
    git clone -b $BRANCH $PYINSTALLER_GIT_URL pyinstaller
fi

cd pyinstaller
git pull
git checkout $BRANCH
$PYTHON setup.py install
cd ..

wine "C:/python$PYTHON_VERSION/scripts/pyinstaller.exe" -v
