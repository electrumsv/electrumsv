The Scaling Test Network
########################

:status: draft
:date: 2020-10-05 16:00
:summary: The best place to test your applications under load is on the scaling test network. This guide shows you how ElectrumSV can be used with it.
:category: guides

As a developer, the best way to do Bitcoin development is to use the test networks that exist for
that purpose. It follows from this, that if there is a test network that has simulated high load
at various levels over time, that this provides a invaluable location to test under more realistic
conditions. And there is such a network, the `scaling test network`__ (otherwise known as the STN).

__ https://bitcoinscaling.io

.. figure:: {static}scaling-testnet/2020-10-05-stn-feature.png
   :align: center
   :width: 90 %
   :alt: The Scaling Test Network web site.

   Featured content from the scaling test network web site.

It is possible to run ElectrumSV against any of the test networks. And being able to select when
you run it, which it runs against, provides a flexible way to use ElectrumSV with any network when
the need arises. The primary use that anyone might make of ElectrumSV is to manage coins.

Managing STN coins with ElectrumSV
----------------------------------

When you run ElectrumSV, it will run against the main network by default. This is where the
official Bitcoin SV coins exist. In order to run ElectrumSV against the STN, a user needs to
provide it with a command-line argument. Unfortunately, there is not currently a way to start
ElectrumSV and then direct it to use the STN through the user interface.

Selecting the STN
~~~~~~~~~~~~~~~~~

There are many ways that you could run ElectrumSV on both your platform and your environment, and
the examples below can be used as a starting point. The key thing shown is that
as long as you are able to work out how to run from your command-line, you need to use
the ``--scaling-testnet`` argument when you do so.

If you are running one of our official Windows builds obtained through this web site, you might
use the following command:

.. code:: console

  ElectrumSV-1.3.6-portable.exe --scaling-testnet

If you are running from source code on Windows, you might use the following command:

.. code:: console

  py -3 electrum-sv --scaling-testnet

And if you are running on macOS or Linux, you might use the following command:

.. code:: console

  electrum-sv --scaling-testnet

Identifying your current network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Which network ElectrumSV is running against, is prominently displayed in the title bar of each
wallet window.

