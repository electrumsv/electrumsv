#!/usr/bin/env bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || exit

cd ${here}/../..

git submodule init
git submodule update

fail=0

exit ${fail}
