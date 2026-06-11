#!/bin/sh
# Script to run tests
#
# Version: 20260609

if test -f ${PWD}/libcaes/.libs/libcaes.1.dylib && test -f ./pycaes/.libs/pycaes.so
then
	install_name_tool -change /usr/local/lib/libcaes.1.dylib ${PWD}/libcaes/.libs/libcaes.1.dylib ./pycaes/.libs/pycaes.so
fi

make check-build > /dev/null

make check $@
RESULT=$?

if test ${RESULT} -ne 0
then
	find . -name \*.log -path \*.dir/\*/\*.log -print -exec cat {} \;
fi
exit ${RESULT}

