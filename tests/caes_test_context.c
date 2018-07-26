/*
 * Library context type test program
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
/* No additional includes necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
#include <openssl/evp.h>
#endif

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )
#define __USE_GNU
#include <dlfcn.h>
#undef __USE_GNU
#endif

#include "caes_test_libcaes.h"
#include "caes_test_libcerror.h"
#include "caes_test_macros.h"
#include "caes_test_memory.h"
#include "caes_test_unused.h"

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
/* No additional function hooks necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

static int (*caes_test_real_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int) = NULL;

int caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail                  = -1;

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

/* Custom EVP_CIPHER_CTX_set_padding for testing error cases
 * Returns 0 if successful or an error value otherwise
 */
int EVP_CIPHER_CTX_set_padding(
     EVP_CIPHER_CTX *c,
     int pad )
{
	int result = 0;

	if( caes_test_real_EVP_CIPHER_CTX_set_padding == NULL )
	{
		caes_test_real_EVP_CIPHER_CTX_set_padding = dlsym(
		                                             RTLD_NEXT,
		                                             "EVP_CIPHER_CTX_set_padding" );
	}
	if( caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail == 0 )
	{
		caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail = -1;

		return( 0 );
	}
	else if( caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail > 0 )
	{
		caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail--;
	}
	result = caes_test_real_EVP_CIPHER_CTX_set_padding(
	          c,
	          pad );

	return( result );
}

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) */

/* Tests the libcaes_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int caes_test_context_initialize(
     void )
{
	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	int result                 = 0;

	/* Test regular cases
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
/* No additional function hooks necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && !defined( HAVE_EVP_CIPHER_CTX_INIT )

	/* Test libcaes_context_initialize with malloc failing in EVP_CIPHER_CTX_new
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
#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) */

#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
/* No additional function hooks necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libcaes_context_initialize with EVP_CIPHER_CTX_set_padding failing
	 */
	caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail = 0;

	result = libcaes_context_initialize(
	          &context,
	          &error );

	if( caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail != -1 )
	{
		caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail = -1;

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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) */

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

/* Tests the libcaes_context_set_key function
 * Returns 1 if successful or 0 if not
 */
int caes_test_context_set_key(
     void )
{
	uint8_t key[ 16 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	int result                 = 0;

	/* Initialize test
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

	/* Test regular cases
	 */
	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libcaes_context_set_key(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
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

	result = libcaes_context_set_key(
	          context,
	          -1,
	          key,
	          128,
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

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          128,
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

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          0,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
/* No additional function hooks necessary */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_context_set_key with memcpy failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) */

	/* Clean up
	 */
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

/* Tests the libcaes_crypt_cbc function
 * Returns 1 if successful or 0 if not
 */
int caes_test_crypt_cbc(
     void )
{
	uint8_t initialization_vector[ 16 ];
	uint8_t input_data[ 16 ];
	uint8_t key[ 16 ];
	uint8_t output_data[ 16 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	size_t maximum_size        = 0;
	int result                 = 0;

	/* Initialize test
	 */
#if defined( HAVE_WINCRYPT ) && defined( WINAPI ) && ( WINVER >= 0x0600 )
	maximum_size = (size_t) UINT32_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
	maximum_size = (size_t) INT_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

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

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libcaes_crypt_cbc(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          -1,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          0,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          NULL,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          maximum_size + 1,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          8,
	          output_data,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          NULL,
	          16,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          maximum_size + 1,
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

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          8,
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

#if defined( HAVE_WINCRYPT ) && defined( WINAPI ) && ( WINVER >= 0x0600 )

	/* TODO test libcaes_crypt_cbc with CryptSetKeyParam failing 2 times */

	/* TODO test libcaes_crypt_cbc with CryptGetKeyParam failing */

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_cbc with memset of block_data failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memset_attempts_before_fail != -1 )
	{
		caes_test_memset_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_crypt_cbc with memcpy of input_data to output_data failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

	/* TODO test libcaes_crypt_cbc with CryptEncrypt failing */

	/* TODO test libcaes_crypt_cbc with CryptDecrypt failing */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_crypt_cbc with memcpy of initialization_vector to safe_initialization_vector failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

	/* TODO test libcaes_crypt_cbc with AES_cbc_encrypt failing */

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_cbc with memset of safe_initialization_vector failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memset_attempts_before_fail != -1 )
	{
		caes_test_memset_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_cbc with memset of block_data failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memset_attempts_before_fail != -1 )
	{
		caes_test_memset_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

	/* TODO test libcaes_crypt_cbc with EVP_CipherInit_ex failing */

	/* TODO test libcaes_crypt_cbc with EVP_CipherUpdate failing */

#else

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_crypt_cbc with memcpy of initialization_vector to internal_initialization_vector failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Test libcaes_crypt_cbc with memcpy of input_data to output_data failing
	 */
	caes_test_memcpy_attempts_before_fail = 1;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_ENCRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Test libcaes_crypt_cbc with memcpy of output_data to internal_initialization_vector failing
	 */
	caes_test_memcpy_attempts_before_fail = 2;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_ENCRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Test libcaes_crypt_cbc with memcpy of input_data to internal_initialization_vector failing
	 */
	caes_test_memcpy_attempts_before_fail = 1;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memcpy_attempts_before_fail != -1 )
	{
		caes_test_memcpy_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_cbc with memset of internal_initialization_vector failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	if( caes_test_memset_attempts_before_fail != -1 )
	{
		caes_test_memset_attempts_before_fail = -1;
	}
	else
	{
		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		CAES_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

#endif /* defined( HAVE_WINCRYPT ) && defined( WINAPI ) && ( WINVER >= 0x0600 ) */

	/* Clean up
	 */
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

/* Tests the libcaes_crypt_ccm function
 * Returns 1 if successful or 0 if not
 */
int caes_test_crypt_ccm(
     void )
{
	uint8_t input_data[ 16 ];
	uint8_t key[ 16 ];
	uint8_t nonce[ 8 ];
	uint8_t output_data[ 16 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	int result                 = 0;

#if defined( HAVE_CAES_TEST_MEMORY )
	int number_of_memset_fail_tests = 1;
	int test_number                 = 0;

#if defined( OPTIMIZATION_DISABLED )
	int number_of_memcpy_fail_tests = 2;
#endif
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

	/* Initialize test
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

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          input_data,
	          16,
	          output_data,
	          16,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libcaes_crypt_ccm(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          -1,
	          nonce,
	          8,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          16,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          15,
	          input_data,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          NULL,
	          16,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          input_data,
	          (size_t) SSIZE_MAX + 1,
	          output_data,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          input_data,
	          16,
	          NULL,
	          16,
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

	result = libcaes_crypt_ccm(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          nonce,
	          8,
	          input_data,
	          16,
	          output_data,
	          (size_t) SSIZE_MAX + 1,
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

#if defined( HAVE_CAES_TEST_MEMORY )

	/* 1 memset of internal_initialization_vector
	 *
	 * TODO determine how many memsets are introduced by libcaes_crypt_ecb
	 * # - 1 memset of block_data
	 * # memset of internal_initialization_vector
	 */
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_context_initialize with memset failing
		 */
		caes_test_memset_attempts_before_fail = test_number;

		result = libcaes_crypt_ccm(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          nonce,
		          8,
		          input_data,
		          16,
		          output_data,
		          16,
		          &error );

		if( caes_test_memset_attempts_before_fail != -1 )
		{
			caes_test_memset_attempts_before_fail = -1;
		}
		else
		{
			CAES_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			CAES_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#if defined( OPTIMIZATION_DISABLED )

	/* 1 memcpy of nonce to internal_initialization_vector
	 * 2 memcpy of input_data cwtoot output_data
	 */
	for( test_number = 0;
	     test_number < number_of_memcpy_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_context_initialize with memcpy failing
		 */
		caes_test_memcpy_attempts_before_fail = test_number;

		result = libcaes_crypt_ccm(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          nonce,
		          8,
		          input_data,
		          16,
		          output_data,
		          16,
		          &error );

		if( caes_test_memcpy_attempts_before_fail != -1 )
		{
			caes_test_memcpy_attempts_before_fail = -1;
		}
		else
		{
			CAES_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			CAES_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( OPTIMIZATION_DISABLED ) */
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

	/* Clean up
	 */
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

	CAES_TEST_RUN(
	 "libcaes_context_initialize",
	 caes_test_context_initialize );

	CAES_TEST_RUN(
	 "libcaes_context_free",
	 caes_test_context_free );

	CAES_TEST_RUN(
	 "libcaes_context_set_key",
	 caes_test_context_set_key );

#if !defined( LIBCAES_HAVE_AES_SUPPORT )

	/* TODO: add tests for libcaes_initialize_tables */

	/* TODO: add tests for libcaes_internal_context_set_decryption_key */

	/* TODO: add tests for libcaes_internal_context_set_encryption_key */

#endif /* !defined( LIBCAES_HAVE_AES_SUPPORT ) */

	CAES_TEST_RUN(
	 "libcaes_crypt_cbc",
	 caes_test_crypt_cbc );

	CAES_TEST_RUN(
	 "libcaes_crypt_ccm",
	 caes_test_crypt_ccm );

	/* TODO: add tests for libcaes_crypt_cfb */

	/* TODO: add tests for libcaes_crypt_ecb */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

