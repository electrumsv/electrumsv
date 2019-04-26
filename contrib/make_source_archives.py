#!/usr/bin/env python3

import os
import subprocess

from electrumsv import version


def get_latest_tag_name() -> str:
    result = subprocess.Popen(['git', 'describe', '--tags', '--abbrev=0', '--match', 'sv-*'],
        stdout=subprocess.PIPE)
    return result.stdout.readline().decode().strip()


def get_tagged_commit(tag_name: str) -> str:
    result = subprocess.Popen(['git','rev-list','-n', '1', tag_name], stdout=subprocess.PIPE)
    return result.stdout.readline().decode().strip()


def get_latest_commit() -> str:
    result = subprocess.Popen(['git','log','--format=%H','-n','1'], stdout=subprocess.PIPE)
    return result.stdout.readline().decode().strip()


def create_git_archive(release_path: str) -> None:
    subprocess.Popen(['git','archive','-o',release_path,'HEAD'], stdout=subprocess.PIPE)


CONTRIB_PATH = os.path.dirname(os.path.realpath(__file__))
REPO_PATH = os.path.join(CONTRIB_PATH, "..")
DIST_PATH = os.path.join(REPO_PATH, "dist")

if not os.path.exists(DIST_PATH):
  os.mkdir(DIST_PATH)

LATEST_TAG_NAME = get_latest_tag_name()
TAGGED_COMMIT = get_tagged_commit(LATEST_TAG_NAME)
LATEST_COMMIT = get_latest_commit()

EXTRA_NAME = "-"+ LATEST_COMMIT[:8] if TAGGED_COMMIT != LATEST_COMMIT else ""

RELEASE_NAME = f"ElectrumSV-{version.PACKAGE_VERSION}{EXTRA_NAME}"

RELEASE_BASEPATHNAME = os.path.realpath(os.path.join(DIST_PATH, RELEASE_NAME))

create_git_archive(RELEASE_BASEPATHNAME +".zip")
create_git_archive(RELEASE_BASEPATHNAME +".tar.gz")
