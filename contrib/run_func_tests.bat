@echo off
@rem "to specify default python version to 3.7 create/edit ~/AppData/Local/py.ini with [default] set to python3=3.7"
set ESVDIR=%~dp0..\

py -3 -m pip install pytest pytest-cov
if %ERRORLEVEL% neq 0 goto ProcessError

@rem "ensuring all components are stopped..."
electrumsv-sdk stop
if %ERRORLEVEL% neq 0 goto ProcessError

@rem "resetting node, simple indexer, reference server and electrumsv..."
electrumsv-sdk install node
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk install simple_indexer
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk install reference_server
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk install --repo=%ESVDIR% electrumsv
if %ERRORLEVEL% neq 0 goto ProcessError

@rem "resetting node, simple indexer, reference server and electrumsv..."
electrumsv-sdk reset node
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk reset simple_indexer
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk reset reference_server
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk reset --repo=%ESVDIR%
if %ERRORLEVEL% neq 0 goto ProcessError

@rem "starting up node, simple indexer, reference server and electrumsv in preparation "
@rem "for functional testing..."
electrumsv-sdk start --background node
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk start --background simple_indexer
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk start --background reference_server
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk start --background --repo=%ESVDIR% electrumsv
if %ERRORLEVEL% neq 0 goto ProcessError

@rem "running functional tests via the electrumsv restapi..."
py -3 -m pytest -v -v -v functional_tests/
if %ERRORLEVEL% neq 0 goto ProcessError

electrumsv-sdk stop
goto Exit

:ProcessError
@rem process error
echo An unexpected error occured, stopping all spawned SDK components...
electrumsv-sdk stop

:Exit
