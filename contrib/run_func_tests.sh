trap "electrumsv-sdk stop" EXIT

set -e

SCRIPT=$(readlink -f $0)
SCRIPTDIR=`dirname $SCRIPT`
ESVDIR=`dirname $SCRIPTDIR`

python3 -m pip install pytest pytest-cov
# "ensuring all components are stopped..."
electrumsv-sdk stop

# "starting up node, simple indexer, reference server and electrumsv in preparation for
#  functional testing..."
electrumsv-sdk install --background node
electrumsv-sdk install --background simple_indexer
electrumsv-sdk install --background reference_server
electrumsv-sdk install --background --repo=$ESVDIR electrumsv

# "resetting node, simple indexer, reference server and electrumsv..."
electrumsv-sdk reset node
electrumsv-sdk reset simple_indexer
electrumsv-sdk reset reference_server
electrumsv-sdk reset --repo=$ESVDIR electrumsv

electrumsv-sdk start --background node
electrumsv-sdk start --background simple_indexer
electrumsv-sdk start --background reference_server
electrumsv-sdk start --background --repo=$ESVDIR electrumsv

# "running functional tests via the electrumsv restapi..."
python3 -m pytest -v -v -v functional_tests/
