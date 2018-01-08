/*
 * Library key type test program
 *
 * Copyright (C) 2011-2018, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "caes_test_libcaes.h"
#include "caes_test_libcerror.h"
#include "caes_test_macros.h"
#include "caes_test_memory.h"
#include "caes_test_unused.h"

#include "../libcaes/libcaes_key.h"

#if defined( WINAPI ) && ( WINVER >= 0x0600 ) && defined( TODO )

/* Tests the libcaes_key_initialize function
 * Returns 1 if successful or 0 if not
 */
int caes_test_key_initialize(
     void )
{
	libcaes_key_t *key              = NULL;
	libcerror_error_t *error        = NULL;
	int result                      = 0;

#if defined( HAVE_CAES_TEST_MEMORY )
	int number_of_malloc_fail_tests = 1;
	int number_of_memset_fail_tests = 1;
	int test_number                 = 0;
#endif

	/* Test regular cases
	 */
	result = libcaes_key_initialize(
	          &key,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "key",
	 key );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libcaes_key_free(
	          &key,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "key",
	 key );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libcaes_key_initialize(
	          NULL,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	key = (libcaes_key_t *) 0x12345678UL;

	result = libcaes_key_initialize(
	          &key,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	key = NULL;

#if defined( HAVE_CAES_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_key_initialize with malloc failing
		 */
		caes_test_malloc_attempts_before_fail = test_number;

		result = libcaes_key_initialize(
		          &key,
		          &error );

		if( caes_test_malloc_attempts_before_fail != -1 )
		{
			caes_test_malloc_attempts_before_fail = -1;

			if( key != NULL )
			{
				libcaes_key_free(
				 &key,
				 NULL );
			}
		}
		else
		{
			CAES_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			CAES_TEST_ASSERT_IS_NULL(
			 "key",
			 key );

			CAES_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_key_initialize with memset failing
		 */
		caes_test_memset_attempts_before_fail = test_number;

		result = libcaes_key_initialize(
		          &key,
		          &error );

		if( caes_test_memset_attempts_before_fail != -1 )
		{
			caes_test_memset_attempts_before_fail = -1;

			if( key != NULL )
			{
				libcaes_key_free(
				 &key,
				 NULL );
			}
		}
		else
		{
			CAES_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			CAES_TEST_ASSERT_IS_NULL(
			 "key",
			 key );

			CAES_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( key != NULL )
	{
		libcaes_key_free(
		 &key,
		 NULL );
	}
	return( 0 );
}

/* Tests the libcaes_key_free function
 * Returns 1 if successful or 0 if not
 */
int caes_test_key_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libcaes_key_free(
	          NULL,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

#endif /* defined( WINAPI ) && ( WINVER >= 0x0600 ) && defined( TODO ) */

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc CAES_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] CAES_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc CAES_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] CAES_TEST_ATTRIBUTE_UNUSED )
#endif
{
	CAES_TEST_UNREFERENCED_PARAMETER( argc )
	CAES_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( WINAPI ) && ( WINVER >= 0x0600 ) && defined( TODO )

	CAES_TEST_RUN(
	 "libcaes_key_initialize",
	 caes_test_key_initialize );

	CAES_TEST_RUN(
	 "libcaes_key_free",
	 caes_test_key_free );

	/* TODO: add tests for libcaes_key_set */

#endif /* defined( WINAPI ) && ( WINVER >= 0x0600 ) && defined( TODO ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

