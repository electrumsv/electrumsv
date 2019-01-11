# Verifying ElectrumSV Downloads using GNU Privacy Guard

## TLDR

    gpg --verify <SIGNATURE> <FILE>

## Detailed Steps
1. Create your private key with

        gpg --generate-key

    Choose RSA/DSA key with 4096 bits.
    Enter your name, email and make sure to choose a strong password.

2. Download the public key of the person/institution you want to verify, all should be in the github repo:

    * Find the directory for the release you are wanting to verify, e.g. https://github.com/electrumsv/electrumsv/tree/sv-1.0.0/pubkeys.  Replace `sv-1.0.0` with the version of your release.
    * Download the keys in that directory.
    * wget https://github.com/electrumsv/electrumsv/blob/sv-1.0.0/pubkeys/Dave.asc

3. Import the keys into your key ring

        gpg --import Dave.asc

    You should see output similar to

        gpg: key ABCDEFABCDEFABC: public key "Dave Smith (DaveySmith)         <dave.smith@example.com>" imported
        gpg: Total number processed: 1
        gpg:               imported: 1

4. You need to sign the person’s public key with your private key, to tell GPG that you “accept” the key.

        gpg --list-keys

        pub   dsa2048 2017-08-20 [SC]
        ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFAB
        uid           [ unknown] Dave Smith (DaveySmith) <dave.smmith@example.com>
        sub   elg2048 2017-08-20 [E]

    The “name” of their key is long string on the second line.

5. Sign their public key with:

        gpg --sign-key ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFAB

6. Download the corresponding signature file

        wget https://electrumsv.io/download/1.0.0/ElectrumSV-1.0.0.exe.asc

7. Now you can verify the signature of the file you downloaded

        gpg --verify ElectrumSV-1.0.0.exe.asc

    Example of successful output

        gpg: assuming signed data in 'ElectrumSV-1.0.0.exe'
        gpg: Signature made Sat  6 Jan 03:51:06 2018 AEDT
        gpg:                using DSA key 21810A542031C02C
        gpg: checking the trustdb
        gpg: marginals needed: 3  completes needed: 1  trust model: pgp
        gpg: depth: 0  valid:   2  signed:   1  trust: 0-, 0q, 0n, 0m, 0f, 2u
        gpg: depth: 1  valid:   1  signed:   0  trust: 1-, 0q, 0n, 0m, 0f, 0u
        gpg: next trustdb check due at 2020-01-12
        gpg: Good signature from "Dave Smith (DaveySmith) <dave.smith@example.com>" [full]

### Installing GnuPG MAC OS
Can be installed using [Homebrew](https://brew.sh/)

    brew install gpg

# Verifying ElectrumSV Downloads using File Hashes
PLEASE NOTE: sha256sum is known as gsha256sum in MACOS

**We do not currently provide file hashes.**

Download the SHA256SUMS file to the same directory as the installer.


Compare the file hashes

    sha256sum -c SHA256.ElectrumSV-3.1-macosx.dmg.txt 2>&1

If the file hashes match, "OK" will be displayed on your screen.

    ElectrumSV-3.1-macosx.dmg: OK

If the hashes do not match, then there was a problem with either the download or a problem with the server. You should download the file again.

## Manual Verification of File Hashes

Download the SHA256SUMS files

    wget https://raw.githubusercontent.com/ElectrumSV/keys-n-hashes/master/sigs-and-sums/3.1/mac/SHA256.ElectrumSV-3.1-macosx.dmg.txt

View the SHA256SUMS file

    cat SHA256.ElectrumSV-3.1-macosx.dmg.txt
    670d6851908720195d58a1d94a53e77e4120e0e98f6940ee93a76f4468e2c6c5  ElectrumSV-3.1-macosx.dmg

Generate a SHA256 hash of the file you downloaded

    sha256sum ElectrumSV-3.1-macosx.dmg
    670d6851908720195d58a1d94a53e77e4120e0e98f6940ee93a76f4468e2c6c5  ElectrumSV-3.1-macosx.dmg

Now compare the hash that your machine calculated with the corresponding hash in the SHA256SUMS file.

When both hashes match exactly then the downloaded file is almost certainly intact.
