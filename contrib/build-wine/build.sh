#!/bin/bash
# Lucky number
export PYTHONHASHSEED=22

BUILD_WINE_PATH="$(dirname $(readlink -f $0))"
CONTRIB_PATH="$BUILD_WINE_PATH/.."

echo "Clearing $BUILD_WINE_PATH/build and $BUILD_WINE_PATH/dist..."
rm "$BUILD_WINE_PATH"/build/* -rf
rm "$BUILD_WINE_PATH"/dist/* -rf

mkdir -p /tmp/electrum-build
mkdir -p /tmp/electrum-build/pip-cache
export PIP_CACHE_DIR="/tmp/electrum-build/pip-cache"

$BUILD_WINE_PATH/prepare-wine.sh || exit 1

echo "Resetting modification time in C:\Python..."
# (Because of some bugs in pyinstaller)
pushd /opt/wine64/drive_c/python*
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd # /opt/wine64/drive_c/python*

ls -l /opt/wine64/drive_c/python*

$BUILD_WINE_PATH/build-electrum-git.sh && echo "Done."
