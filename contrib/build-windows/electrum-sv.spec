# -*- mode: python -*-

import os
import pathlib
import sys

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_data_files, PY_DYLIB_PATTERNS

# This is primarily so that psutil will have this available and ElectrumSV will not error when
# started and `electrum-sv` errors.
if "*.pyd" not in PY_DYLIB_PATTERNS:
    PY_DYLIB_PATTERNS.append("*.pyd")

block_cipher = None
cmdline_name = "ElectrumSV"

import electrumsv
home = pathlib.Path(electrumsv.__path__[0])

libusb_dll_path = pathlib.Path("libusb-1.0.dll")
libzbar_dll_path = pathlib.Path("libzbar-0.dll")

assert libusb_dll_path.exists(), "libusb dll not found, run.py should have placed in top level"
assert libzbar_dll_path.exists(), "libzbar dll not found, run.py should have placed in top level"

# Add libusb binary
binaries = [
    (str(libusb_dll_path), "."),
    (str(libzbar_dll_path), "."),
]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'qwindowsvista' in b[0]]

datas = [
    (str(home / 'data'), 'electrumsv/data'),
]
datas += collect_data_files('bitcoinx')
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')
datas += collect_data_files('electrumsv_secp256k1')
binaries += collect_dynamic_libs('psutil')

a = Analysis([ os.path.join("Scripts", 'electrum-sv') ],
             pathex=[],
             binaries=binaries,
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use to reduce binary size
# Note we need qtdbus and qtprintsupport.
qt_bins2remove = {'qt5web', 'qt53d', 'qt5game', 'qt5designer', 'qt5quick',
                  'qt5location', 'qt5test', 'qt5xml', r'pyqt5\qt\qml\qtquick',
                  'qt5webwockets', 'd3dcompiler', 'libegl', 'libgles',
                  'opengl'}
for x in a.binaries.copy():
    lower_path = x[0].lower()
    for keyword in qt_bins2remove:
        if keyword in lower_path:
            print(f'----> Removed: {x[0]}')
            a.binaries.remove(x)

qt_data2remove=(r'pyqt5\qt\translations\qtwebengine_locales', )
print("Removing Qt datas:", *qt_data2remove)
for x in a.datas.copy():
    for r in qt_data2remove:
        if x[0].lower().startswith(r.lower()):
            a.datas.remove(x)
            print(f'----> Removed: {x[0]}')

# hotfix for #3171 (pre-Win10 binaries)
a.binaries = [x for x in a.binaries if not x[1].lower().startswith(r'c:\windows')]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    # The normal way that PyInstaller works is to embed the PKG archive in the executable which allows it to be signed.
    # We want it kept separate in order to give us the ability to experiment with alternative bootloading.
    name='electrumsv',
    debug=False,
    bootloader_ignore_signals=False,
    icon=str(home / "data" / "icons" / "electrum-sv.ico"),
    strip=False,
    upx=False,
    console=False)

coll = COLLECT(exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ElectrumSV')

exe_standalone = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=cmdline_name + ".exe",
    debug=False,
    strip=None,
    upx=False,
    icon=str(home / "data" / "icons" / "electrum-sv.ico"),
    console=False)

exe_portable = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas + [ ('is_portable', 'README.rst', 'DATA' ) ],
    name=cmdline_name + "-portable.exe",
    debug=False,
    strip=None,
    upx=False,
    icon=str(home / "data" / "icons" / "electrum-sv.ico"),
    console=False)

#####
# exe and separate files that NSIS uses to build installer "setup" exe

exe_dependent = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=cmdline_name,
    debug=False,
    strip=None,
    upx=False,
    icon=str(home / "data" / "icons" / "electrum-sv.ico"),
    console=False)

coll = COLLECT(
    exe_dependent,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    debug=False,
    icon=str(home / "data" / "icons" / "electrum-sv.ico"),
    console=False,
    name=cmdline_name +"-setup.exe")
