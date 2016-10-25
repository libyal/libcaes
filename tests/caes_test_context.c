/*
 * Library context type testing program
 *
 * Copyright (C) 2011-2016, Joachim Metz <joachim.metz@gmail.com>
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
#include "caes_test_libcstring.h"
#include "caes_test_macros.h"
#include "caes_test_memory.h"
#include "caes_test_unused.h"

/* Tests the libcaes_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int caes_test_context_initialize(
     void )
{
	libcerror_error_t *error   = NULL;
	libcaes_context_t *context = NULL;
	int result                 = 0;

	/* Test libcaes_context_initialize
	 */
	result = libcaes_context_initialize(
	          &context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        CAES_TEST_ASSERT_IS_NOT_NULL(
         "context",
         context );

        CAES_TEST_ASSERT_IS_NULL(
         "error",
         error );

	result = libcaes_context_free(
	          &context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

        CAES_TEST_ASSERT_IS_NULL(
         "context",
         context );

        CAES_TEST_ASSERT_IS_NULL(
         "error",
         error );

	/* Test error cases
	 */
	result = libcaes_context_initialize(
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

	context = (libcaes_context_t *) 0x12345678UL;

	result = libcaes_context_initialize(
	          &context,
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

	context = NULL;

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_context_initialize with malloc failing
	 */
	caes_test_malloc_attempts_before_fail = 0;

	result = libcaes_context_initialize(
	          &context,
	          &error );

	if( caes_test_malloc_attempts_before_fail != -1 )
	{
		caes_test_malloc_attempts_before_fail = -1;

		if( context != NULL )
		{
			libcaes_context_free(
			 &context,
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
		 "context",
		 context );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Test libcaes_context_initialize with memset failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_context_initialize(
	          &context,
	          &error );

	if( caes_test_memset_attempts_before_fail != -1 )
	{
		caes_test_memset_attempts_before_fail = -1;

		if( context != NULL )
		{
			libcaes_context_free(
			 &context,
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
		 "context",
		 context );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( context != NULL )
	{
		libcaes_context_free(
		 &context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libcaes_context_free function
 * Returns 1 if successful or 0 if not
 */
int caes_test_context_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libcaes_context_free(
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

/* The main program
 */
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
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

	CAES_TEST_RUN(
	 "libcaes_context_initialize",
	 caes_test_context_initialize );

	CAES_TEST_RUN(
	 "libcaes_context_free",
	 caes_test_context_free );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

