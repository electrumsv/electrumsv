# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
import os

PACKAGE='ElectrumSV'
PYPKG='electrumsv'
MAIN_SCRIPT='electrum-sv'
ICONS_FILE='contrib/osx/electrum-sv.icns'

for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    raise Exception('no version')

home_dir = os.path.abspath(".") + "/"
block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('trezorlib')
hiddenimports += collect_submodules('btchip')
hiddenimports += collect_submodules('keepkeylib')
hiddenimports += collect_submodules('websocket')
# Keepkey imports PyQt5.Qt.  Provide our own until they fix it
hiddenimports.remove('keepkeylib.qt.pinmatrix')

datas = [
    (home_dir + PYPKG + '/*.json', PYPKG),
    (home_dir + PYPKG + '/wordlist/english.txt', PYPKG + '/wordlist'),
    (home_dir + PYPKG + '/locale', PYPKG + '/locale'),
    (home_dir + PYPKG + '/plugins', PYPKG + '/plugins'),
]
datas += collect_data_files('trezorlib')
datas += collect_data_files('btchip')
datas += collect_data_files('keepkeylib')

# Add the QR Scanner helper app
datas += [(home_dir + "contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app", "./contrib/osx/CalinsQRReader/build/Release/CalinsQRReader.app")]

binaries = [(home_dir + "contrib/osx/libsecp256k1.0.dylib", ".")]

# Workaround for "Retro Look":
binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([home_dir +  MAIN_SCRIPT,
              home_dir + 'electrumsv/gui/qt/main_window.py',
              home_dir + 'electrumsv/util.py',
              home_dir + 'electrumsv/wallet.py',
              home_dir + 'electrumsv/simple_config.py',
              home_dir + 'electrumsv/bitcoin.py',
              home_dir + 'electrumsv/dnssec.py',
              home_dir + 'electrumsv/commands.py',
              home_dir + 'electrumsv/plugins/cosigner_pool/qt.py',
              home_dir + 'electrumsv/plugins/email_requests/qt.py',
              home_dir + 'electrumsv/plugins/trezor/qt.py',
              home_dir + 'electrumsv/plugins/keepkey/qt.py',
              home_dir + 'electrumsv/plugins/ledger/qt.py',
              ],
             binaries=binaries,
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[])

# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use to reduce binary size
# Note we need qtdbus and qtprintsupport.
qt_bins2remove = {
    'qtquick', 'qtwebsockets', 'qtnetwork', 'qtqml',
}
print("Searching for Qt binaries to remove...")
for x in a.binaries.copy():
    lower = x[0].lower()
    if lower in qt_bins2remove:
        a.binaries.remove(x)
    elif lower.startswith('qt'):
        print('----> Keeping ', x)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.datas,
          name=PACKAGE,
          debug=False,
          strip=False,
          upx=True,
          icon=home_dir + ICONS_FILE,
          console=False)

app = BUNDLE(exe,
             version = VERSION,
             name=PACKAGE + '.app',
             icon=home_dir + ICONS_FILE,
             bundle_identifier=None,
             info_plist={
                'NSHighResolutionCapable': 'True',
                'NSSupportsAutomaticGraphicsSwitching': 'True'
             }
)
