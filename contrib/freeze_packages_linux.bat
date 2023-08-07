@echo off
REM Change directory to 'electrumsv'
cd ..

REM Build the Docker image
docker build -t freeze-packages -f contrib/Dockerfile .

REM Run the Docker container, execute a command, and then immediately exit
docker run --rm -it ^
    --network=host ^
    --name freeze-packages ^
    -v %cd%\contrib\deterministic-build:/electrumsv/contrib/deterministic-build ^
    freeze-packages ^
    /bin/bash -c "python contrib/freeze_packages.py"
