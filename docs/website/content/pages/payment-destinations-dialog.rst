The Payment Destination window
==============================

:date: 2020-05-28 16:00
:modified: 2020-09-08 16:00
:authors: The ElectrumSV Developers
:tags: guide
:summary: Information about the various features available in the payment destination window.

This window allows you to view the unused payment destinations that the given
account will use next. In some cases these will be standard Bitcoin addresses,
and in other cases where the script type has no address form, the BIP276 standard
will be used to present them.

Possible dangers
----------------

The destinations listed here are not reserved. If you take them and use them
elsewhere, there is no guarantee that ElectrumSV won't also proceed to use them
in the course of it's normal wallet usage on your behalf.
