The ElectrumSV node project
===========================

:date: 2021-06-10 20:00
:modified: 2021-06-10 20:00
:authors: The ElectrumSV Developers
:url: node-project/
:save_as: node-project/index.html
:tags: guide
:summary: Pre-compiled builds of the Bitcoin SV node made available for developers to use.
:unfurlimage: articles/electrumsv-node-0.0.23/20210601-bitcoinsv-node-software.png

It is very useful for Bitcoin developers to have access to builds of the Bitcoin SV node software
to test their applications against. The ElectrumSV developers already compile builds for their own
use and this project is intended to make those available for any developers who are building on
Bitcoin SV to obtain and use these as needed.

.. important::

   The current build of `electrumsv-node` is `0.0.23`, which includes the Bitcoin SV node version
   `1.0.8` (64 bit only). Instructions on how to verify your downloads are linked in our
   documentation.

You can read `the documentation`__ for this project, which includes instructions on how to verify
these builds are authentic, install them and run them.

__ https://electrumsv-node.readthedocs.io/en/latest/

Currently available builds
--------------------------

This is the only build we currently support. If you have a problem with these files, you can
`talk to us`__ about it. If you are using older builds which we no longer support, it is
recommended that you upgrade and see if your problem is resolved with the latest build.

__ https://github.com/electrumsv/electrumsv-node/issues

.. table:: The currently supported builds.
   :widths: auto
   :align: center
   :width: 100%

   ========= ============ ======================================= =============
   Platform  Node version File                                    File size
   ========= ============ ======================================= =============
   MacOS     1.0.8        `electrumsv-node-macos-0.0.23.zip`__    3.8 MB
   Windows   1.0.8        `electrumsv-node-windows-0.0.23.zip`__  8.0 MB
   ========= ============ ======================================= =============

__ https://electrumsv-downloads.s3.us-east-2.amazonaws.com/node-releases/0.0.23/electrumsv-node-macos-0.0.23.zip
__ https://electrumsv-downloads.s3.us-east-2.amazonaws.com/node-releases/0.0.23/electrumsv-node-windows-0.0.23.zip

Be aware that Bitcoin node software is commonly integrated into malware, where the malware authors
use the compromised computers to mine cryptocurrencies. Because of this, it is very likely that you
will need to work around your browser and virus checker to download these files, in order to avoid
the false positives. We provide instructions in our documentation to help you verify that the
files you download here are the ones we made available.