#!/bin/bash

BUILD_WINE_PATH="$(dirname $(readlink -f $0))"
CONTRIB_PATH="$BUILD_WINE_PATH/.."

# Please update these carefully, some versions won't work under Wine
NSIS_FILENAME=nsis-3.05-setup.exe
NSIS_URL=https://prdownloads.sourceforge.net/nsis/$NSIS_FILENAME?download
NSIS_SHA256=1a3cc9401667547b9b9327a177b13485f7c59c2303d4b6183e7bc9e6c8d6bfdb

ZBAR_FILENAME=zbarw-20121031-setup.exe
ZBAR_URL=https://sourceforge.net/projects/zbarw/files/$ZBAR_FILENAME/download
ZBAR_SHA256=177e32b272fa76528a3af486b74e9cb356707be1c5ace4ed3fcee9723e2c2c02

LIBUSB_REPO='https://github.com/libusb/libusb.git'
LIBUSB_COMMIT=a5990ab10f68e5ec7498f627d1664b1f842fec4e

LIBZBAR_REPO='https://github.com/mchehab/zbar.git'
LIBZBAR_COMMIT=aac86d5f08d64ab4c3da78188eb622fa3cb07182

PYINSTALLER_REPO="https://github.com/pyinstaller/pyinstaller.git"
PYINSTALLER_COMMIT="4b9fd01d7dc5a0aae3ba7c100437547915464f0e"

PYTHON_VERSION=3.10.7

## These settings probably don't need change
export WINEPREFIX=/opt/wine64

PYTHON_FOLDER="python3"
PYHOME="c:/$PYTHON_FOLDER"
PYTHON="wine $PYHOME/python.exe -OO -B"

# based on https://superuser.com/questions/497940/script-to-verify-a-signature-with-gpg
verify_signature() {
    local file=$1 keyring=$2 out=
    if out=$(gpg --no-default-keyring --keyring "$keyring" --status-fd 1 --verify "$file" 2>/dev/null) &&
       echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG "; then
        return 0
    else
        echo "$out" >&2
        exit 1
    fi
}

verify_hash() {
    local file=$1 expected_hash=$2
    actual_hash=$(sha256sum $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        exit 1
    fi
}

download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
        local retrycount=0
        set +e
        wget -O $PWD/$file_name "$url"
        # Sourceforge has sporadic connectivity problems, perhaps related to DDOS. They advise
        # retrying. We'll retry 5 times.
        while [[ $? != 0 && $retrycount < 5 ]]; do
            sleep 1
            retrycount=$(($retrycount + 1))
            echo wget rety attempt $retrycount for $url
            wget -c --tries=3 --retry-connrefused --waitretry=3 -O $PWD/$file_name "$url"
        done
        if [ $? -ne 0 ]; then
            exit $?
        fi
        set -e
    fi
}

# Let's begin!
set -e

wine 'wineboot'

pushd /tmp/electrum-build

# Install Python
# note: you might need "sudo apt-get install dirmngr" for the following
# keys from https://www.python.org/downloads/#pubkeys
echo "Downloading Python dev keyring (may take a few minutes)..."
KEYRING_PYTHON_DEV=keyring-electrumsv-build-python-dev.gpg
# The recv keys path just takes ages and randomly fails.  Checking in the keys from https://www.python.org/downloads/#pubkeys.
gpg --no-default-keyring --keyring $KEYRING_PYTHON_DEV --import $BUILD_WINE_PATH/python-pubkeys.txt
for msifile in core dev exe lib pip tools; do
    echo "Installing $msifile..."
    wget -N -c "https://www.python.org/ftp/python/$PYTHON_VERSION/amd64/${msifile}.msi"
    wget -N -c "https://www.python.org/ftp/python/$PYTHON_VERSION/amd64/${msifile}.msi.asc"
    verify_signature "${msifile}.msi.asc" $KEYRING_PYTHON_DEV
    wine msiexec /i "${msifile}.msi" /qb TARGETDIR=$PYHOME
done

# upgrade pip
$PYTHON -m pip install pip --upgrade
$PYTHON -m pip install -r $CONTRIB_PATH/deterministic-build/win64-py3.10-requirements-pyinstaller.txt

echo "Compiling PyInstaller bootloader with anti-virus false-positive protection"
pushd $WINEPREFIX/drive_c/electrum
GIT_COMMIT_HASH=$(git rev-parse HEAD)
popd # $WINEPREFIX/drive_c/electrum

mkdir pyinstaller
(
    cd pyinstaller
    # Shallow clone
    git init
    git remote add origin $PYINSTALLER_REPO
    git fetch --depth 1 origin $PYINSTALLER_COMMIT
    git checkout -b pinned "${PYINSTALLER_COMMIT}^{commit}"
    # This errors with it not picking up commctrl.h definitions for some reason. Disable it for now.
    rm -fv PyInstaller/bootloader/Windows-*/run*.exe || true  # Make sure EXEs that came with repo are deleted -- we rebuild them and need to detect if build failed
    if [ ${PYI_SKIP_TAG:-0} -eq 0 ] ; then
        echo "const char *ec_tag = \"tagged by ElectrumSV@$GIT_COMMIT_HASH\";" >> ./bootloader/src/pyi_main.c
    else
        warn "Skipping PyInstaller tag"
    fi
    pushd bootloader
    # If switching to 64-bit Windows, edit CC= below
    export WINRC=`which x86_64-w64-mingw32-windres`
    python3 ./waf all CC=x86_64-w64-mingw32-gcc CFLAGS="-Wno-stringop-overflow -static"
    # Note: it's possible for the EXE to not be there if the build
    # failed but didn't return exit status != 0 to the shell (waf bug?);
    # So we need to do this to make sure the EXE is actually there.
    # If we switch to 64-bit, edit this path below.
    popd
    [ -e PyInstaller/bootloader/Windows-64bit/runw.exe ] || { echo "Could not find runw.exe in target dir!" ; exit 1; }
) || { echo "PyInstaller bootloader build failed" ; exit 1; }
echo "Installing PyInstaller ..."
$PYTHON -m pip install ./pyinstaller || { echo "PyInstaller install failed" ; exit 1; }

wine "$PYHOME/scripts/pyinstaller.exe" -v || { echo "Pyinstaller installed but cannot be run." ; exit 1; }

# Upgrade setuptools (so Electrum can be installed later)
$PYTHON -m pip install setuptools --upgrade

# Install NSIS installer
download_if_not_exist $NSIS_FILENAME "$NSIS_URL"
verify_hash $NSIS_FILENAME "$NSIS_SHA256"
wine "$PWD/$NSIS_FILENAME" /S

echo "Compiling libzbar ..."
mkdir libzbar
(
    pushd libzbar
    # Shallow clone
    git init
    git remote add origin $LIBZBAR_REPO
    git fetch --depth 1 origin $LIBZBAR_COMMIT
    git checkout -b pinned FETCH_HEAD
    export SOURCE_DATE_EPOCH=1530212462
    echo "libzbar_la_LDFLAGS += -Wc,-static" >> zbar/Makefile.am
    echo "LDFLAGS += -Wc,-static" >> Makefile.am
    autoreconf -vfi || { echo "Could not run autoreconf for $pkgname. Please make sure you have automake and libtool installed, and try again."; exit 1; }
    host="x86_64-w64-mingw32"
    ./configure \
        $AUTOCONF_FLAGS \
        --prefix="$BUILD_WINE_PATH/libzbar/dist" \
        --host=$host \
        --build=x86_64-pc-linux-gnu \
        --with-x=no \
        --enable-video=yes \
        --with-jpeg=no \
        --with-directshow=yes \
        --disable-dependency-tracking \
        --enable-pthread=no \
        --enable-doc=no \
        --with-python=no \
        --with-gtk=no \
        --with-qt=no \
        --with-java=no \
        --with-imagemagick=no \
        --with-dbus=no \
        --enable-codes=qrcode \
        --disable-static \
        --enable-shared || { echo "Could not configure libzbar. Please make sure you have a C compiler installed and try again."; exit 1; }
    make -j4 || { echo "Could not build libzbar" ; exit 1; }
    make install || { echo "Could not install libzbar" ; exit 1; }
    . "$BUILD_WINE_PATH/libzbar/dist/lib/libzbar.la"
    ${host}-strip $BUILD_WINE_PATH/libzbar/dist/bin/libzbar-0.dll
    popd # libzbar
) || { echo "libzbar build failed" ; exit 1; }

cp $BUILD_WINE_PATH/libzbar/dist/bin/libzbar-0.dll $WINEPREFIX/drive_c/$PYTHON_FOLDER/ || { echo "Could not copy libzbar to its destination" ; exit 1; }

echo "Compiling libusb ..."
mkdir libusb
(
    pushd libusb
    # Shallow clone
    git init
    git remote add origin $LIBUSB_REPO
    git fetch --depth 1 origin $LIBUSB_COMMIT
    git checkout -b pinned FETCH_HEAD
    export SOURCE_DATE_EPOCH=1530212462
    echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am
    ./bootstrap.sh || { echo "Could not bootstrap libusb" ; exit 1; }
    host="x86_64-w64-mingw32"
    LDFLAGS="-Wl,--no-insert-timestamp" ./configure \
        --host=$host \
        --build=x86_64-pc-linux-gnu || { echo "Could not run ./configure for libusb" ; exit 1; }
    make -j4 || { echo "Could not build libusb" ; exit 1; }
    ${host}-strip libusb/.libs/libusb-1.0.dll
    popd # libusb
) || { echo "libusb build failed" ; exit 1; }

cp libusb/libusb/.libs/libusb-1.0.dll $WINEPREFIX/drive_c/$PYTHON_FOLDER/ || { echo "Could not copy libusb to its destination" ; exit 1; }

popd # /tmp/electrum-build

echo "Wine is configured."
