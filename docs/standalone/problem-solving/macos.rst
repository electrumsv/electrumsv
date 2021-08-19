MacOS issues
============

Problems launching ElectrumSV
-----------------------------

There are various different obstacles users may encounter when they try to run ElectrumSV depending
on which version of the operating system they are using. We'll illustrate each below and explain
what it means, and what you can do about it.

"damaged and can't be opened"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a bug in the operating system. What it means is that the file you downloaded is unsigned
and they won't run it or give you the standard ways to work around it involving the Security
Center. There is a workaround which you can do, but it involves you using the terminal.

.. figure:: images/macos-damaged-dms.png
   :alt: The message shown because of Apple's bug
   :align: center
   :scale: 50%

Workaround
^^^^^^^^^^

The solution to this is the following steps:

1. Open the terminal. If you do not know how, you can go to Launchpad enter "terminal" as you
   would any other application name in the search area, and click on it. Note that you do not
   enter the " characters around the word when you search for it.
2. It is expected that you have the ElectrumSV dmg file you get this error with in your Downloads
   directory. You can use the "cd" command to change your directory to get there, using
   ``cd Downloads``.
3. You need to type something close to ``xattr -rd com.apple.quarantine <filename>``. However, you
   need to replace "<filename>" with the filename of the ElectrumSV dmg file you are getting this
   error with. If for instance you downloaded "ElectrumSV-1.4.0b1.dmg", then you would need to
   execute the command ``xattr -rd com.apple.quarantine ElectrumSV-1.4.0b1.dmg``.

What this does is it removes the flag Apple put on the file when you downloaded it, to indicate
it was not safe. You should be now be able to run it, having applied the workaround.

Startup takes a long time
~~~~~~~~~~~~~~~~~~~~~~~~~

When you run the dmg and then click on the ElectrumSV logo to start it, does it take a long long
time to start? This was never that fast, but it has become slower as we started including the
blockchain headers in our application in order to provide a higher quality experience and to
prepare for the coming of a new technology called SPV.

Workaround
^^^^^^^^^^

Install the application and run it as an installed application, rather than launching it from the
dmg. This should reduce the time considerably that it takes from when you start the installed
application to when you see the first window it opens.

1. Open the dmg file.
2. Observe there is an ElectrumSV icon on the left hand side, and a folder on the right hand side
   with an arrow pointing from the icon to the folder.
3. Drag the icon into the folder.

ElectrumSV should now be installed and you should be able to use Launchpad to start it or whatever
you prefer to do to get applications you have installed to run.
