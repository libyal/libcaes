#!/bin/sh
# Script to run tests
#
# Version: 20201121

if test -f ${PWD}/libcaes/.libs/libcaes.1.dylib && test -f ./pycaes/.libs/pycaes.so;
then
	install_name_tool -change /usr/local/lib/libcaes.1.dylib ${PWD}/libcaes/.libs/libcaes.1.dylib ./pycaes/.libs/pycaes.so;
fi

make check CHECK_WITH_STDERR=1;
RESULT=$?;

if test ${RESULT} -ne 0 && test -f tests/test-suite.log;
then
	cat tests/test-suite.log;
fi
exit ${RESULT};

