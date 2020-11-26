Hardware wallet issues
======================

Trezor
------

While Trezor as a company do not support Bitcoin SV as a coin on their device. Generally Bitcoin SV
users have been able to use their Trezor devices with ElectrumSV by having it in the Bitcoin Cash
coin mode. However, users are encountering situations where the limitations of the Trezor device
result in it no being longer sufficient to work with Bitcoin SV transactions. This likely means
that if a user is planning to continue to use a Trezor device, it may require them to jump through
hoops to do so.

There are two complications:

- Later versions of firmware (starting with 1.9.1 for One and 2.3.0 for Model T) require ElectrumSV
  to pass in parent transactions with the transaction you are signing. ElectrumSV only started
  supporting this in ElectrumSV 1.3.8 or newer. What this means is that if you are using these
  later versions of firmware, you must be using ElectrumSV 1.3.8 or newer - or it will error.
- Bitcoin SV transactions can have large output scripts, larger than what Trezor can handle.
  Trezor can only sign simple payments and nothing else, but this does not prevent payments from
  being made into the wallet with additional output scripts added for other reasons that exceed
  Trezor's size limit of 15 kilobytes. The parent transaction processing in the Trezor device will
  error when it encounters these.

Trezor devices are becoming problematic for Bitcoin SV users to use. While they are polished and
enjoyable devices to use, unless the large output problem is solved by Trezor, we cannot
recommend users buy these devices unless they accept they have to own and deal with these problems.
For this reason it is recommended that Trezor users downgrade their devices.

Downgrading your Trezor device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These are Trezor's firmware version pages, for users who plan to downgrade:

- Trezor One: `1.9.0 <https://github.com/trezor/webwallet-data/blob/master/firmware/1/trezor-1.9.0.bin>`_.
- Trezor Model T: `2.3.0 <https://github.com/trezor/webwallet-data/blob/master/firmware/2/trezor-2.3.0.bin>`_.

You will need to visit those pages and download the firmware file. Trezor
`provide instructions <https://wiki.trezor.io/Firmware_downgrade>`_ on how to downgrade, and
let you know how and where to use the file.

Problem: You see a random looking series of numbers and letters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. figure:: images/trezor-01-parent-tx-unsupported.jpg
   :alt: What this problem looks like..
   :align: center
   :scale: 80%

   What this problem looks like..

You are using ElectrumSV 1.3.7 or earlier, and your Trezor device has a later version of the
firmware. It expects ElectrumSV to have provided the transaction associated with those numbers
and letters, but the ElectrumSV version you are using does not know how to or even that it should.
You can take the risk of updating to a more recent version of ElectrumSV that supports these
parent transactions, and possibly encounter the "DataError: bytes overflow" problem. Or you can
downgrade your Trezor firmware to the version listed above.

Problem: You see the message "DataError: bytes overflow"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. figure:: images/trezor-02-output-script-too-big.png
   :alt: What this problem looks like..
   :align: center
   :scale: 80%

   What this problem looks like..

One of your parent transactions contains not only the coin you are trying to spend, but a large
output script. Your Trezor device has a later version of firmware where parent transactions are
required to be provided, and the device is choking on the large output. This is a limit in the
device itself, and ElectrumSV can do nothing about this. To spend the coin associated with the
problem parent transaction, you need to downgrade your firmware to the versions listed above.
