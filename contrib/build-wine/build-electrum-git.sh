#!/bin/bash

NAME_ROOT=ElectrumSV

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export WINEDEBUG=fixme-all
export PYTHONDONTWRITEBYTECODE=1
export WINEDEBUG=fixme-all
export PYTHONHASHSEED=22

PYHOME=c:/python3
PYTHON="wine $PYHOME/python.exe -OO -B"

BUILD_WINE_PATH="$(dirname $(readlink -f $0))"
CONTRIB_PATH="$BUILD_WINE_PATH/.."

# Let's begin!
cd `dirname $0`
echo `pwd`
set -e

mkdir -p tmp
pushd tmp

pushd $WINEPREFIX/drive_c/electrum

# --dirty: If there are local modifications, add the '-dirty' text.
# --always: If we are not directly on a tag, add the abbreviated commit.
# --match: Only consider tags matching the given pattern.
# e.g. "sv-1.1.0-12-f3d2d22" (12 commits past tag, and on commit f3d2d22)
RAW_VERSION=`git describe --tags --dirty --always --match sv-*`
# Strip the leading 3 characters from the description, 'sv-1.1.0' -> '1.1.0' (the release version).
VERSION=${RAW_VERSION:3}
echo "Last commit description: $VERSION"

find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd # $WINEPREFIX/drive_c/electrum

cp $WINEPREFIX/drive_c/electrum/LICENCE .

# Install frozen dependencies
$PYTHON -m pip install setuptools==57.1.0
$PYTHON -m pip install -r ../../deterministic-build/win64-py3.10-requirements-electrumsv.txt

pushd $WINEPREFIX/drive_c/electrum
$PYTHON -m pip install .
popd # $WINEPREFIX/drive_c/electrum

popd # tmp

rm -rf dist/

# build standalone and portable versions ... --name $NAME_ROOT-$VERSION
wine "$PYHOME/scripts/pyinstaller.exe" --noconfirm --ascii --clean deterministic.spec

# set timestamps in dist, in order to make the installer reproducible (we do not actually care)
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd # dist

# build NSIS installer
# $VERSION could be passed to the electrum.nsi script, but this would require some rewriting in the script iself.
wine "$WINEPREFIX/drive_c/Program Files (x86)/NSIS/makensis.exe" /DPRODUCT_VERSION=$VERSION electrum.nsi

pushd dist
mv ElectrumSV-portable.exe $NAME_ROOT-$VERSION-portable.exe
mv ElectrumSV-setup.exe $NAME_ROOT-$VERSION-setup.exe
mv ElectrumSV.exe $NAME_ROOT-$VERSION.exe

cp $BUILD_WINE_PATH/libzbar/dist/bin/libzbar-0.dll .
cp /tmp/electrum-build/libusb/libusb/.libs/libusb-1.0.dll .
ls -l
popd

echo "Done."
sha256sum dist/*.*
