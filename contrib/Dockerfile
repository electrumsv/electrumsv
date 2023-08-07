FROM python:3.10
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libegl1-mesa \
    libxkbcommon0 \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
COPY . /electrumsv
RUN python -m pip install pip==22.2.2 --disable-pip-version-check
WORKDIR /electrumsv/contrib
RUN python -m pip install \
    -r requirements/requirements.txt \
    -r requirements/requirements-dev.txt \
    -r requirements/requirements-electrumsv.txt \
    -r requirements/requirements-hw.txt
WORKDIR /electrumsv
RUN python -m pytest electrumsv/tests
CMD sleep infinity
# Then run the freeze_packages.py script (see freeze_packages_linux.bat)