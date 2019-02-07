Deterministic Windows binaries with Docker
==========================================

This assumes an Ubuntu host, but it should not be too hard to adapt to another
similar system.

1. Install Docker

    ```
    $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    $ sudo apt-get update
    $ sudo apt-get install -y docker-ce
    ```

2. Build image

    ```
    $ cd contrib/build-wine/docker
    $ PROJECT_ROOT=$PWD/../../../
    $ sudo docker build --no-cache -t electrum-wine-builder-img .
    ```

    Note: see [this](https://stackoverflow.com/a/40516974/7499128) if having dns problems

3. Build Windows binaries

    It's recommended to build from a fresh clone
    (but you can skip this if reproducibility is not necessary).

    ```
    $ FRESH_CLONE=contrib/build-wine/fresh_clone && \
        rm -rf $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone https://github.com/electrumsv/electrumsv.git && \
        cd electrumsv
    ```

    And then build from this directory:
    ```
    $ git checkout $REV
    $ sudo docker run -it \
        --name electrumsv-wine-builder-cont \
        -v $PWD:/opt/wine64/drive_c/electrum \
        --rm \
        --workdir /opt/wine64/drive_c/electrum/contrib/build-wine \
        electrumsv-wine-builder-img \
        ./build.sh
    ```
4. The generated binaries are in `$PROJECT_ROOT/contrib/build-wine/dist`.



Note: the `setup` binary (NSIS installer) is not deterministic yet.
