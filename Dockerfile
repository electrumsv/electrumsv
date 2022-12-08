FROM python:3.10

RUN apt-get update
RUN apt-get -y install libusb-1.0.0-dev libudev-dev
RUN apt-get -y install zbar-tools

COPY . .
RUN python3 -m pip install pip==22.2.2 --disable-pip-version-check
RUN python3 -m pip install -r contrib/deterministic-build/linux-py3.10-requirements.txt --disable-pip-version-check
RUN python3 -m pip install -r contrib/deterministic-build/linux-py3.10-requirements-hw.txt --disable-pip-version-check

# start of fix - include until soltuion is merged into bitcoinx.
RUN python3 -m pip uninstall bitcoinx -y
RUN python3 -m pip install git+https://github.com/kyuupichan/bitcoinX.git@61634bebe4d877111c1be8c583ec28d00845ba75
# end of fix

RUN mkdir -p /electrumsv/data/wallets

EXPOSE 9999
CMD sleep infinity
