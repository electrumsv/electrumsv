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
    "google2fc36430d2cd4ae1.html",
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

DOWNLOAD_LATEST = DownloadEntry("1.3.13", "2021/05/04", "/articles/2021/electrumsv-1_3_13.html", [
    DownloadFileEntry("fab fa-apple", "MacOS downloads", "MacOS", "ElectrumSV-1.3.13-signed.dmg","30.8 MiB"),
    DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.13.exe", "26.8 MiB"),
    DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.13-portable.exe", "26.8 MiB"),
    DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.13.tar.gz", "9.0 MiB"),
    DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.13.zip", "9.3 MiB"),
    DownloadFileEntry("fas fa-book", "Documentation", "HTML", "ElectrumSV-1.3.13-docs.zip", "10.3 MiB"),
])

DOWNLOADS_OLDER = [
    DownloadEntry("1.3.12", "2021/04/23", "https://medium.com/@roger-taylor/electrumsv-1-3-12-a4002e6dbdf6", [
        DownloadFileEntry("fab fa-apple", "MacOS downloads", "MacOS", "ElectrumSV-1.3.12.dmg","30.5 MiB"),
        DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.12.exe", "26.9 MiB"),
        DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.3.12-portable.exe", "26.9 MiB"),
        DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.12.tar.gz", "7.6 MiB"),
        DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.3.12.zip", "7.9 MiB"),
        DownloadFileEntry("fas fa-book", "Documentation", "HTML", "ElectrumSV-1.3.12-docs.zip", "10.3 MiB"),
    ])
]

DOWNLOADS_EXPERIMENTAL = [
    # DownloadEntry("1.4.0b1", "2021/08/19", "/articles/2021/electrumsv-1_4_0b1.html", [
    #     DownloadFileEntry("fab fa-apple", "MacOS downloads", "MacOS", "ElectrumSV-1.4.0b1.dmg","78.5 MiB"),
    #     DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.4.0b1.exe", "74.0 MiB"),
    #     DownloadFileEntry("fab fa-windows", "Windows downloads", "Windows", "ElectrumSV-1.4.0b1-portable.exe", "74.0 MiB"),
    #     DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.4.0b1.tar.gz", "56.0 MiB"),
    #     DownloadFileEntry("fas fa-code", "Other downloads", "Source code", "ElectrumSV-1.4.0b1.zip", "56.4 MiB"),
    #     DownloadFileEntry("fas fa-book", "Documentation", "HTML", "ElectrumSV-1.4.0b1-docs.zip", "11.0 MiB"),
    # ], "Due to Apple's new security requirements, please read <a href='https://electrumsv.readthedocs.io/en/releases-1.4/problem-solving/macos.html#damaged-and-can-t-be-opened'>our workaround</a> for a problem you may encounter."),
]

# The maximum number articles to include on a page.
DEFAULT_PAGINATION = 10

PAGINATED_TEMPLATES = {'index': 3 }

# Uncomment following line if you want document-relative URLs when developing
RELATIVE_URLS = True
