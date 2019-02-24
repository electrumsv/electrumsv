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

binaries = [(base_dir + "contrib/osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

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
ICONS_FILE='contrib/osx/ElectrumSV.icns'

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=version.PACKAGE_VERSION,
          debug=False,
          strip=False,
          upx=True,
          icon=base_dir + ICONS_FILE,
          console=False)

app = BUNDLE(exe,
             version=version.PACKAGE_VERSION,
             name=PACKAGE + '.app',
             icon=base_dir + ICONS_FILE,
             bundle_identifier=None,
             info_plist={
                'NSHighResolutionCapable': 'True',
                'NSSupportsAutomaticGraphicsSwitching': 'True'
             }
)
