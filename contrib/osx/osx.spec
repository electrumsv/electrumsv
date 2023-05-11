# -*- mode: python -*-

from importlib.machinery import SourceFileLoader
import os

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_data_files

version = SourceFileLoader('version', 'electrumsv/version.py').load_module()

# The directory with the electrum-sv script
base_dir = os.path.abspath(".") + "/"

datas = [
    (base_dir + 'electrumsv/data', 'electrumsv/data'),
    (base_dir + "contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app",
     "CalinsQRReader.app"),
]

# rt12 -- As far as I know only trezor has required data files. It will error if it cannot load
# things like coins.json and so on.
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')
# Pretty sure this collects nothing, but it's necessary on Windows, so here for completeness.
# MacOS seems to get the shared library dependencies automatically, perhaps because they are
# linked in via a binary python extension, which follows from wheel creation behaving the same
# way (as compared to Windows where the shared library is loaded from Python dynamically).
datas += collect_data_files('electrumsv_secp256k1')

# Workaround for "Retro Look":
binaries = [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]
binaries += [(base_dir + "contrib/osx/libusb-1.0.dylib", ".")]

a = Analysis([base_dir + 'electrum-sv'], binaries=binaries, datas=datas)

# Strip out parts of Qt that we never use to reduce binary size
# Note we need qtdbus and qtprintsupport.
remove = {'qtquick', 'qtwebsockets', 'qtnetwork', 'qtqml'}
for x in a.binaries.copy():
    lower = x[0].lower()
    if lower in remove:
        a.binaries.remove(x)

if False:
    from pprint import pprint
    for key in 'scripts', 'pure', 'binaries', 'datas':
        print(f'a.{key}:')
        pprint(getattr(a, key))

PACKAGE='ElectrumSV'
BUNDLE_IDENTIFIER='io.electrumsv.' + PACKAGE
ICONS_FILE='contrib/osx/ElectrumSV.icns'

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=version.PACKAGE_VERSION,
    debug=False,
    strip=False,
    upx=True,
    icon=base_dir + ICONS_FILE,
    console=False)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    version=version.PACKAGE_VERSION,
    name=PACKAGE + '.app',
    icon=base_dir + ICONS_FILE,
    bundle_identifier=BUNDLE_IDENTIFIER,
    info_plist={
        'NSHighResolutionCapable': 'True',
        'NSSupportsAutomaticGraphicsSwitching': 'True',
        'NSCameraUsageDescription': 'Need to use camera to read QR Codes'
    }
)
