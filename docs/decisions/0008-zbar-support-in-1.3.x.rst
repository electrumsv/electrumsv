QR Scanning the native ZBar Dependency in 1.3.x
###############################################

:Date: 2023-05-22
:Status: Completed.
:Author: AustEcon

Context
-------
Brief Summary
^^^^^^^^^^^^^
The 1.3.x branches use zbar for the camera to scan QR codes.
Zbar has bugs related to camera window scaling for some Windows users.
While we could upgrade this support, we have decided not to.

Detailed Explanation:
^^^^^^^^^^^^^^^^^^^^^
The existing 1.3.15 release of ElectrumSV uses an old version of the zbar dll
which halted maintainance in 2012 (see: https://github.com/ZBar/ZBar ).

Maintenance was taken over in a forked version (see: https://github.com/mchehab/zbar )
and this is what most people use now including ElectrumSV's develop branch, Electrum and
Electron-Cash. However, in all of these cases, they do not let zbar manage the image
acquisition or accessing the camera. This is done via the PyQt6 QtCamera feature and
the pre-processed image array data is submitted to zbar for interpretation.

By letting PyQt6 manage the camera, this sidesteps an unresolved issue related to scaling of
the initial window size. See: https://github.com/spesmilo/electrum/issues/6018

Running v1.3.15 (using "old zbar") on my windows 11 system, I can reproduce this identical error. ::

    Assertion failed: img->datalen == bufferlen, file video/dshow.c, line 548

This error is also reproducible with the "new" zbar and the zbarcam.exe built-in executable.
(See compilation instructions below).
- Fresh install of msys2 on windows.
- Compile with instructions from https://github.com/mchehab/zbar/blob/master/README-windows.md ::

    pacman -Syu –noconfirm autoconf libtool automake make autoconf-archive pkg-config gettext-devel
    pacman -S git
    git clone https://github.com/mchehab/zbar.git
    cd zbar
    pacman -S mingw-w64-i686-gcc
    autoreconf -vfi ./configure
        –host=i686-w64-mingw32 –prefix=/usr/local/win32
        –without-gtk –without-python –without-qt –without-java
        –without-imagemagick –enable-pthread
        –with-directshow –disable-dependency-tracking
    make
    make install

Run the built-in zbarcam.exe with the `prescale` option set ::

    $ zbar\zbarcam\bin> .\zbarcam.exe --prescale=640x480
    Assertion failed: img->datalen == bufferlen, file video/dshow.c, line 548

Without the `prescale` option, the window loads without error but the initial window size is impractically large.

The 1.3.x series uses a 32-bit version of python and PyQt5.
PyQt6 only releases wheels for 64-bit python. So even if we were willing to proceed
with fully migrating 1.3.x to the equivalent solution used in the develop branch,
it would require moving to 64-bit python, upgrading all UI code to PyQt6 and porting
the changes across to use the QtCamera + new zbar dll with the new ctypes bindings.

This is a large commitment to support QR Reading in a legacy version of ElectrumSV and
given competing work on our backlog, the investment cannot be justified.

Other considerations:
a) We do not currently have any users complaining about QR Reading not working with 1.3.15
b) QR Reading with 1.3.15 works on Roger's machine so it is hard to say how many users are
even affected.
c) QR Scanning is non-essential wallet functionality. It does not preclude usage of all other
wallet features. If they really want QR Scanning functionality, they can start using the latest
1.4.x version of ElectrumSV.


Decision
--------

No further work is to be done on the 1.3.x series of releases in regards to QR code scanning.

Consequences
------------

- Some users (but not all) will have issues with QR Scanning but it's not worth it to fix
for the amount of work involved.
