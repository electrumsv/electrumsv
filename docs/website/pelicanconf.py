#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from typing import List, NamedTuple

AUTHOR = 'ElectrumSV Developers'
SITENAME = 'ElectrumSV Website'
SITEURL = ''
PAGEDESC = 'This page is currently lacking a description. Contact the developers and let them know.'
PAGEIMG = "https://electrumsv.io/theme/img/ESV_atomicon_RGB_small.png"

THEME = "theme"

PATH = "content"
PAGE_PATHS = [ "pages" ]
ARTICLE_PATHS = [ "articles" ]
STATIC_PATHS = [
    "download",
    "release.json",
    "BingSiteAuth.xml",
]

ARTICLE_SAVE_AS = 'articles/{date:%Y}/{slug}.html'
ARTICLE_URL = 'articles/{date:%Y}/{slug}.html'

TEMPLATE_PAGES = {
    "download.html": "download.html",
}

TIMEZONE = 'Pacific/Auckland'

DEFAULT_LANG = 'en'
DEFAULT_DATE_FORMAT = "%Y/%m/%d %I:%M %p"

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

class DownloadFileEntry(NamedTuple):
    class_name: str
    title: str
    text: str
    file_name: str
    size_text: str

class DownloadEntry(NamedTuple):
    version: str
    release_date: str
    article_link: str
    files: List[DownloadFileEntry]
    extra_text: str = ""

DOWNLOAD_LATEST = DownloadEntry("1.3.16", "2023/05/23", "/articles/2023/electrumsv-1_3_16.html", [
    DownloadFileEntry("fab fa-apple", "MacOS downloads", "MacOS", "ElectrumSV-1.3.16.dmg","31.2 MiB"),
    DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.16.exe", "28.4 MiB"),
    DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.16-portable.exe", "28.4 MiB"),
    DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.16.tar.gz", "9.0 MiB"),
    DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.16.zip", "9.4 MiB"),
    DownloadFileEntry("fas fa-book", "Documentation", "HTML", "ElectrumSV-1.3.16-docs.zip", "4.8 MiB"),
])

DOWNLOADS_OLDER = [
]

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
RELATIVE_URLS = True
