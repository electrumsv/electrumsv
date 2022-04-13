#!/bin/bash
#
# Copied from Electrum Core on 2022/04/13. Electrum Core license (follows this paragraph) applies
# to copied code, Bitcoin SV license applies to any subsequent modifications.
#
# ------- >8 -- Electrum Core license as of 2022/04/13 -- 8< -------
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# ------- >8 -- Electrum Core license as of 2022/04/13 -- 8< -------
#

LIBUSB_VERSION="c6a35c56016ea2ab2f19115d2ea1e85e0edae155"
# ^ tag v1.0.24

set -e

. $(dirname "$0")/build_tools_util.sh || (echo "Could not source build_tools_util.sh" && exit 1)

here=$(dirname $(realpath "$0" 2> /dev/null || grealpath "$0"))
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="libusb"
info "Building $pkgname..."

(
    cd $CONTRIB
    if [ ! -d libusb ]; then
        git clone https://github.com/libusb/libusb.git
    fi
    cd libusb
    if ! $(git cat-file -e ${LIBUSB_VERSION}) ; then
        info "Could not find requested version $LIBUSB_VERSION in local clone; fetching..."
        git fetch --all
    fi
    git reset --hard
    git clean -dfxq
    git checkout "${LIBUSB_VERSION}^{commit}"

    if [ "$BUILD_TYPE" = "wine" ] ; then
        echo "libusb_1_0_la_LDFLAGS += -Wc,-static" >> libusb/Makefile.am
    fi
    ./bootstrap.sh || fail "Could not bootstrap libusb"
    if ! [ -r config.status ] ; then
        if [ "$BUILD_TYPE" = "wine" ] ; then
            # windows target
            LDFLAGS="-Wl,--no-insert-timestamp"
        elif [ $(uname) == "Darwin" ]; then
            # macos target
            LDFLAGS="-Wl -lm"
        else
            # linux target
            LDFLAGS=""
        fi
        LDFLAGS="$LDFLAGS" ./configure \
            $AUTOCONF_FLAGS \
            || fail "Could not configure $pkgname. Please make sure you have a C compiler installed and try again."
    fi
    make -j4 || fail "Could not build $pkgname"
    make install || warn "Could not install $pkgname"
    . "$here/$pkgname/libusb/.libs/libusb-1.0.la"
    host_strip "$here/$pkgname/libusb/.libs/$dlname"
    TARGET_NAME="$dlname"
    if [ $(uname) == "Darwin" ]; then  # on mac, dlname is "libusb-1.0.0.dylib"
        TARGET_NAME="libusb-1.0.dylib"
    fi
    cp -fpv "$here/$pkgname/libusb/.libs/$dlname" "$PROJECT_ROOT/electrumsv/$TARGET_NAME" || fail "Could not copy the $pkgname binary to its destination"
    info "$TARGET_NAME has been placed in the inner 'electrumsv' folder."
    if [ -n "$DLL_TARGET_DIR" ] ; then
        cp -fpv "$here/$pkgname/libusb/.libs/$dlname" "$DLL_TARGET_DIR/$TARGET_NAME" || fail "Could not copy the $pkgname binary to DLL_TARGET_DIR"
    fi
)
