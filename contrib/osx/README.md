Building Mac OS binaries
========================

This guide explains how to build ElectrumSV binaries for macOS systems.
We build our binaries on Big Sur (10.15) as this is the current release
of MacOS and we do not have the manpower or resources to commit to
supporting people that cannot upgrade their computer unfortunately.

## 1. Building the binary

This needs to be done on a system running macOS or OS X Big Sur or later.

Before starting, make sure that the Xcode command line tools are
installed (e.g. you have `git`).

#### 1.1 Get Xcode

Building the QR scanner (CalinsQRReader) requires full Xcode (not just
command line tools).

#### 1.2 Build ElectrumSV

    cd electrum-sv
    ./contrib/osx/make_osx

On success this will creates build artifacts in the `dist` folder. A
directory named `ElectrumSV.app` and the `.dmg` file packaging that
app into an installer.

## 2. Code signing builds

With each version of MacOS, Apple requires more and more security checks
before users can run any out of store applications they download.

* An unsigned application will run but fail with a buggy looking warning
  about the application being damaged. This just means it is unsigned and
  Apple intentionally decided to give a misleading message, or perhaps
  sloppily failed to notify the user correctly and this is actually a bug.
* A signed application will require two levels of confirmation from the
  user in the Security Center, before MacOS will let it run.
* A signed and notarised application will simply ask the user if they are
  sure they wish to run a file they downloaded from the internet, and
  allow them to run it if they click okay.

### 2.1 Signing

If you are doing local development, you will not be able to notarise your
build. Ensure you do not have the three environment variables set that you
would have, for notarisation. Then start the build and signing process
with your certificate name.

    ./contrib/make_osx "Mac Developer: <developer name> (BSASA23SAS)"

### 2.2 Signing and notarisation

In order to perform notarisation after code-signing the user should set
three environment variables before they run the build process.

    export APPLE_ID_USER=<Your Apple ID>
    export APPLE_ID_PASSWORD=<Your password>
    export APPLE_ID_PROVIDER=<Your provider id>

The password does not have to be your Apple ID password, instead in the
Developer site you can create an application password that can be used
for signing instead.

The provider ID is around 10 letters and contains upper-case letters 
mixed with numbers. It usually can be found in your Developer ID certificate
name, but you can get it other ways. It is necessary in case your Apple ID
is associated with multiple Apple Developer accounts.

In the following command, you would substitute the single argument with the
name of your signing certificate, which might look quite similar. The
dummy "ASASA23SAS" value would be pone place where you see your provider ID.

    ./contrib/make_osx "Developer ID Application: <developer name> (ASASA23SAS)"

This should complete successfully, leaving the completely signed and notarised
DMG file in the `dist` folder. Apple recommends only notarising the external
container, which for out of store is the DMG. When we are building an installer
to publish in the App store, this will likely be the PKG file.

## 3. References

* [Signing a Mac Product For Distribution](https://developer.apple.com/forums/thread/128166).
* [Testing a Notarised Product](https://developer.apple.com/forums/thread/130560).
* [Checking DMG notarization. Rejected, but works fine](https://developer.apple.com/forums/thread/675354).
