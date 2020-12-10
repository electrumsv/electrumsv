trap "electrumsv-sdk stop" EXIT

set -e

SCRIPT=$(readlink -f $0)
SCRIPTDIR=`dirname $SCRIPT`
ESVDIR=`dirname $SCRIPTDIR`

python3 -m pip install pytest pytest-cov
# "ensuring all components are stopped..."
electrumsv-sdk stop

# "starting up node, electrumx and electrumsv in preparation for functional testing..."
electrumsv-sdk install --background node
electrumsv-sdk install --background electrumx
electrumsv-sdk install --background --repo=$ESVDIR electrumsv

# "resetting node, electrumx and electrumsv..."
electrumsv-sdk reset node
electrumsv-sdk reset electrumx
electrumsv-sdk reset --repo=$ESVDIR electrumsv

electrumsv-sdk start --background node
electrumsv-sdk start --background electrumx
electrumsv-sdk start --background --repo=$ESVDIR electrumsv

# "running functional tests via the electrumsv restapi..."
python3 -m pytest -v -v -v functional_tests/
