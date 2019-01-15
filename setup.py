#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import imp
import argparse

from setuptools import setup, find_packages

if sys.version_info[:3] < (3, 6, 0):
    sys.exit("Error: ElectrumSV requires Python version >= 3.6.0...")

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'electrumsv/version.py')

def copy_dir(dir_name):
    file_path = os.getcwd()
    for (dirpath, dirnames, files) in os.walk(os.path.join(file_path, dir_name)):
        for f in files:
            yield os.path.join(dirpath[len(file_path)+1:], f)

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--user', dest='is_user', action='store_true', default=False)
    parser.add_argument('--system', dest='is_user', action='store_false', default=False)
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    parser.add_argument('--prefix=', dest='prefix_path', metavar='prefix', nargs='?', const='/', default=sys.prefix)
    opts, _ = parser.parse_known_args(sys.argv[1:])

    # Use per-user */share directory if the global one is not writable or if a per-user installation
    # is attempted
    user_share   = os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
    system_share = os.path.join(opts.prefix_path, "share")
    if not opts.is_user:
        # Not neccarily a per-user installation try system directories
        if os.access(opts.root_path + system_share, os.W_OK):
            # Global /usr/share is writable for us – so just use that
            share_dir = system_share
        elif not os.path.exists(opts.root_path + system_share) and os.access(opts.root_path, os.W_OK):
            # Global /usr/share does not exist, but / is writable – keep using the global directory
            # (happens during packaging)
            share_dir = system_share
        else:
            # Neither /usr/share (nor / if /usr/share doesn't exist) is writable, use the
            # per-user */share directory
            share_dir = user_share
    else:
        # Per-user installation
        share_dir = user_share
    data_files += [
        # Menu icon
        (os.path.join(share_dir, 'icons/hicolor/128x128/apps/'), ['data/icons/electrum-sv.png']),
        (os.path.join(share_dir, 'pixmaps/'),                    ['data/icons/electrum-sv.png']),
        # Menu entry
        (os.path.join(share_dir, 'applications/'), ['electrum-sv.desktop']),
        ('', [ file_name for file_name in copy_dir('data') ]),
    ]

setup(
    name="ElectrumSV",
    version=version.PACKAGE_VERSION,
    install_requires=requirements + ['pyqt5'],
    extras_require={
        'hardware': requirements_hw,
    },
    packages=[
        'electrumsv',
        'electrumsv.gui',
        'electrumsv.gui.qt',
        'electrumsv.plugins',
    ] + [('electrumsv.plugins.' + pkg)
         for pkg in find_packages('electrumsv/plugins')],
    package_dir={ # rt12: Pretty sure this does nothing.
        'electrumsv': 'electrumsv'
    },
    package_data={
        'electrumsv': [
            'servers.json',
            'servers_testnet.json',
            'currencies.json',
            'www/index.html',
        ]
    },
    scripts=['electrum-sv'],
    data_files=data_files,
    description="Lightweight Bitcoin SV Wallet",
    author="Roger Taylor",
    author_email="roger.taylor.email@gmail.com",
    license="MIT Licence",
    url="http://electrumsv.io",
    long_description="""Lightweight Bitcoin SV Wallet"""
)
