#!/bin/sh
# Script to run tests
#
# Version: 20260714

if [ -f "${PWD}/libcaes/.libs/libcaes.1.dylib" ] && [ -f ./pycaes/.libs/pycaes.so ]
then
    install_name_tool -change /usr/local/lib/libcaes.1.dylib "${PWD}/libcaes/.libs/libcaes.1.dylib" ./pycaes/.libs/pycaes.so
fi

make check-build > /dev/null

# shellcheck disable=SC2068
make check $@
RESULT=$?

if [ ${RESULT} -ne 0 ]
then
    find . -name \*.log -path \*.dir/\*/\*.log -print -exec cat {} \;
fi
exit ${RESULT}

