#!/usr/bin/env bash

RED='\033[0;31m'
BLUE='\033[0,34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
function info {
	printf "\r💬 ${BLUE}INFO:${NC}  ${1}\n"
}
function fail {
    printf "\r🗯 ${RED}ERROR:${NC}  ${1}\n"
    exit 1
}
function warn {
	printf "\r⚠️  ${YELLOW}WARNING:${NC}  ${1}\n"
}

function DoCodeSignMaybe { # ARGS: infoName fileOrDirName codesignIdentity
    infoName="$1"
    file="$2"
    identity="$3"
    deep=""
    if [ -z "$identity" ]; then
        # we are ok with them not passing anything; master script calls us unconditionally even if no identity is specified
        return
    fi
    if [ -d "$file" ]; then
        deep="--deep"
    fi
    if [ -z "$infoName" ] || [ -z "$file" ] || [ -z "$identity" ] || [ ! -e "$file" ]; then
        fail "Argument error to internal function DoCodeSignMaybe()"
    fi
        hardened_arg="--entitlements=contrib/osx/entitlements.plist -o runtime"

    info "Code signing ${infoName}..."
    codesign -f -v $deep -s "$identity" $hardened_arg "$file" || fail "Could not code sign ${infoName}"
}

verify_hash() {
    local file=$1 expected_hash=$2
    actual_hash=$(shasum -a 256 $file | awk '{print $1}')
    if [ "$actual_hash" == "$expected_hash" ]; then
        return 0
    else
        echo "$file $actual_hash (unexpected hash)" >&2
        exit 1
    fi
}
