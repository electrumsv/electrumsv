# -*- mode: python -*-

from importlib.machinery import SourceFileLoader
import os
import sys

from PyInstaller.utils.hooks import collect_dynamic_libs

version = SourceFileLoader('version', 'electrumsv/version.py').load_module()

# The directory with the electrum-sv script
base_dir = os.path.abspath(".") + "/"

datas = [
    (base_dir + 'data', 'data'),
    (base_dir + "contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app",
     "CalinsQRReader.app"),
]

binaries = [(base_dir + "contrib/osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

a = Analysis([base_dir + 'electrum-sv'], binaries=binaries, datas=datas)

# http://stackoverflow.com/questions/19055089
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use to reduce binary size
# Note we need qtdbus and qtprintsupport.
qt_bins2remove = {'qtquick', 'qtwebsockets', 'qtnetwork', 'qtqml'}
for x in a.binaries.copy():
    lower = x[0].lower()
    if lower in qt_bins2remove:
        a.binaries.remove(x)

PACKAGE='ElectrumSV'
ICONS_FILE='contrib/osx/electrum-sv.icns'

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
