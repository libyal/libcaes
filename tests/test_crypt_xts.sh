#!/bin/bash
# Library AES-XTS de/encryption testing script
#
# Version: 20160217

EXIT_SUCCESS=0;
EXIT_FAILURE=1;
EXIT_IGNORE=77;

TEST_PREFIX=`pwd`;
TEST_PREFIX=`dirname ${TEST_PREFIX}`;
TEST_PREFIX=`basename ${TEST_PREFIX} | sed 's/^lib//'`;

test_crypt_xts()
{ 
	echo "Testing AES-XTS de/encryption";

	TMPDIR="tmp$$";

	rm -rf ${TMPDIR};
	mkdir ${TMPDIR};

	${TEST_RUNNER} ${TMPDIR} ${TEST_CRYPT_XTS};

	RESULT=$?;

	rm -rf ${TMPDIR};

	echo "";

	return ${RESULT};
}

if ! test -z ${SKIP_LIBRARY_TESTS};
then
	exit ${EXIT_IGNORE};
fi

TEST_CRYPT_XTS="./${TEST_PREFIX}_test_crypt_xts";

if ! test -x ${TEST_CRYPT_XTS};
then
	TEST_CRYPT_XTS="${TEST_PREFIX}_test_crypt_xts.exe";
fi

if ! test -x ${TEST_CRYPT_XTS};
then
	echo "Missing executable: ${TEST_CRYPT_XTS}";

	exit ${EXIT_FAILURE};
fi

TEST_RUNNER="tests/test_runner.sh";

if ! test -x ${TEST_RUNNER};
then
	TEST_RUNNER="./test_runner.sh";
fi

if ! test -x ${TEST_RUNNER};
then
	echo "Missing test runner: ${TEST_RUNNER}";

	exit ${EXIT_FAILURE};
fi

if ! test_crypt_xts;
then
	exit ${EXIT_FAILURE};
fi

exit ${EXIT_SUCCESS};

