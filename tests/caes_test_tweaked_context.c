/*
 * Library tweaked_context type test program
 *
 * Copyright (C) 2011-2023, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H )
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

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS )

static int (*caes_test_real_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int)                                                                    = NULL;
static int (*caes_test_real_EVP_CipherInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *, int) = NULL;
static int (*caes_test_real_EVP_CipherUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int)                               = NULL;

int caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail                                                                                     = -1;
int caes_test_EVP_CipherInit_ex_attempts_before_fail                                                                                              = -1;
int caes_test_EVP_CipherUpdate_attempts_before_fail                                                                                               = -1;

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS )

/* Custom EVP_CIPHER_CTX_set_padding for testing error cases
 * Returns 1 if successful or 0 otherwise
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

/* Custom EVP_CipherInit_ex for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int EVP_CipherInit_ex(
     EVP_CIPHER_CTX *ctx,
     const EVP_CIPHER *type,
     ENGINE *impl,
     const unsigned char *key,
     const unsigned char *iv,
     int enc )
{
	int result = 0;

	if( caes_test_real_EVP_CipherInit_ex == NULL )
	{
		caes_test_real_EVP_CipherInit_ex = dlsym(
		                                    RTLD_NEXT,
		                                    "EVP_CipherInit_ex" );
	}
	if( caes_test_EVP_CipherInit_ex_attempts_before_fail == 0 )
	{
		caes_test_EVP_CipherInit_ex_attempts_before_fail = -1;

		return( 0 );
	}
	else if( caes_test_EVP_CipherInit_ex_attempts_before_fail > 0 )
	{
		caes_test_EVP_CipherInit_ex_attempts_before_fail--;
	}
	result = caes_test_real_EVP_CipherInit_ex(
	          ctx,
	          type,
	          impl,
	          key,
	          iv,
	          enc );

	return( result );
}

/* Custom EVP_CipherUpdate for testing error cases
 * Returns 1 if successful or 0 otherwise
 */
int EVP_CipherUpdate(
     EVP_CIPHER_CTX *ctx,
     unsigned char *out,
     int *outl,
     const unsigned char *in,
     int inl )
{
	int result = 0;

	if( caes_test_real_EVP_CipherUpdate == NULL )
	{
		caes_test_real_EVP_CipherUpdate = dlsym(
		                                   RTLD_NEXT,
		                                   "EVP_CipherUpdate" );
	}
	if( caes_test_EVP_CipherUpdate_attempts_before_fail == 0 )
	{
		caes_test_EVP_CipherUpdate_attempts_before_fail = -1;

		return( 0 );
	}
	else if( caes_test_EVP_CipherUpdate_attempts_before_fail > 0 )
	{
		caes_test_EVP_CipherUpdate_attempts_before_fail--;
	}
	result = caes_test_real_EVP_CipherUpdate(
	          ctx,
	          out,
	          outl,
	          in,
	          inl );

	return( result );
}

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

/* Tests the libcaes_tweaked_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int caes_test_tweaked_context_initialize(
     void )
{
	libcaes_tweaked_context_t *tweaked_context = NULL;
	libcerror_error_t *error                   = NULL;
	int result                                 = 0;

#if defined( HAVE_CAES_TEST_MEMORY )
	int number_of_malloc_fail_tests            = 3;
	int number_of_memset_fail_tests            = 1;
	int test_number                            = 0;
#endif

	/* Test regular cases
	 */
	result = libcaes_tweaked_context_initialize(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "tweaked_context",
	 tweaked_context );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libcaes_tweaked_context_free(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "tweaked_context",
	 tweaked_context );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libcaes_tweaked_context_initialize(
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

	tweaked_context = (libcaes_tweaked_context_t *) 0x12345678UL;

	result = libcaes_tweaked_context_initialize(
	          &tweaked_context,
	          &error );

	tweaked_context = NULL;

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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H )
	/* No additional test definitions needed */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && !defined( HAVE_EVP_CIPHER_CTX_INIT ) && defined( HAVE_EVP_CRYPTO_AES_XTS )
	number_of_malloc_fail_tests = 2;

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && !defined( HAVE_EVP_CIPHER_CTX_INIT ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )
	number_of_malloc_fail_tests = 5;

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) */

	/* 1 fail in memory_allocate_structure
	 * 2 fail in memory_allocate_structure of libcaes_context_initialize of main context or in EVP_CIPHER_CTX_new
	 * 3 fail in memory_allocate_structure of libcaes_context_initialize of tweak context or in EVP_CIPHER_CTX_new of libcaes_context_initialize
	 * 4 fail in memory_allocate_structure of libcaes_context_initialize of tweak context
	 * 5 fail in EVP_CIPHER_CTX_new of libcaes_context_initialize of tweak context
	 */
	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_tweaked_context_initialize with malloc failing
		 */
		caes_test_malloc_attempts_before_fail = test_number;

		result = libcaes_tweaked_context_initialize(
		          &tweaked_context,
		          &error );

		if( caes_test_malloc_attempts_before_fail != -1 )
		{
			caes_test_malloc_attempts_before_fail = -1;

			if( tweaked_context != NULL )
			{
				libcaes_tweaked_context_free(
				 &tweaked_context,
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
			 "tweaked_context",
			 tweaked_context );

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
		/* Test libcaes_tweaked_context_initialize with memset failing
		 */
		caes_test_memset_attempts_before_fail = test_number;

		result = libcaes_tweaked_context_initialize(
		          &tweaked_context,
		          &error );

		if( caes_test_memset_attempts_before_fail != -1 )
		{
			caes_test_memset_attempts_before_fail = -1;

			if( tweaked_context != NULL )
			{
				libcaes_tweaked_context_free(
				 &tweaked_context,
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
			 "tweaked_context",
			 tweaked_context );

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
	if( tweaked_context != NULL )
	{
		libcaes_tweaked_context_free(
		 &tweaked_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libcaes_tweaked_context_free function
 * Returns 1 if successful or 0 if not
 */
int caes_test_tweaked_context_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libcaes_tweaked_context_free(
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

/* Tests the libcaes_tweaked_context_set_keys function
 * Returns 1 if successful or 0 if not
 */
int caes_test_tweaked_context_set_keys(
     void )
{
	uint8_t key[ 16 ];
	uint8_t tweak_key[ 16 ];

	libcaes_tweaked_context_t *tweaked_context = NULL;
	libcerror_error_t *error                   = NULL;
	int result                                 = 0;

	/* Initialize test
	 */
	result = libcaes_tweaked_context_initialize(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "tweaked_context",
	 tweaked_context );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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
	result = libcaes_tweaked_context_set_keys(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          -1,
	          key,
	          128,
	          tweak_key,
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

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          128,
	          tweak_key,
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

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          0,
	          tweak_key,
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

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
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

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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
	/* No additional test definitions needed */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS )

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_tweaked_context_set_key with memcpy failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_tweaked_context_set_keys with memcpy failing in libcaes_context_set_key of main context
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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
	/* Test libcaes_tweaked_context_set_keys with memcpy failing in libcaes_context_set_key of tweak context
	 */
	caes_test_memcpy_attempts_before_fail = 1;

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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
	result = libcaes_tweaked_context_free(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "tweaked_context",
	 tweaked_context );

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
	if( tweaked_context != NULL )
	{
		libcaes_tweaked_context_free(
		 &tweaked_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libcaes_crypt_xts function
 * Returns 1 if successful or 0 if not
 */
int caes_test_crypt_xts(
     void )
{
	uint8_t input_data[ 200 ];
	uint8_t key[ 16 ];
	uint8_t output_data[ 200 ];
	uint8_t tweak_key[ 16 ];
	uint8_t tweak_value[ 16 ];

	libcaes_tweaked_context_t *tweaked_context = NULL;
	libcerror_error_t *error                   = NULL;
	size_t maximum_size                        = 0;
	int result                                 = 0;

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS )
	maximum_size = (size_t) INT_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

	/* Initialize test
	 */
	result = libcaes_tweaked_context_initialize(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NOT_NULL(
	 "tweaked_context",
	 tweaked_context );

	CAES_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libcaes_tweaked_context_set_keys(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          tweak_key,
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
	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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
	result = libcaes_crypt_xts(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          -1,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          0,
	          input_data,
	          200,
	          output_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          NULL,
	          200,
	          output_data,
	          200,
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

	if( maximum_size > 0 )
	{
		result = libcaes_crypt_xts(
		          tweaked_context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          tweak_value,
		          16,
		          input_data,
		          maximum_size + 1,
		          output_data,
		          200,
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
	}
	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          0,
	          output_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          NULL,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
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

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS )

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_xts with memset of block_data failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libcaes_crypt_xts with EVP_CipherInit_ex failing
	 */
	caes_test_EVP_CipherInit_ex_attempts_before_fail = 0;

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
	          &error );

	if( caes_test_EVP_CipherInit_ex_attempts_before_fail != -1 )
	{
		caes_test_EVP_CipherInit_ex_attempts_before_fail = -1;
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
	/* Test libcaes_crypt_xts with EVP_CipherUpdate failing
	 */
	caes_test_EVP_CipherUpdate_attempts_before_fail = 0;

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
	          &error );

	if( caes_test_EVP_CipherUpdate_attempts_before_fail != -1 )
	{
		caes_test_EVP_CipherUpdate_attempts_before_fail = -1;
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
#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#else

#if defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED )

	/* Test libcaes_crypt_xts with memcpy of input_data to output_data failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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
/* Even though optimization should be disabled here earlier versions of GNU C do optimize this memcpy
 */
#if __GNUC__ > 5

	/* Test libcaes_crypt_xts with memcpy of encrypted_tweak_value to encrypted_tweak_value_copy failing
	 */
	caes_test_memcpy_attempts_before_fail = 1;

	result = libcaes_crypt_xts(
	          tweaked_context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          tweak_value,
	          16,
	          input_data,
	          200,
	          output_data,
	          200,
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
#endif /* __GNUC__ > 5 */
#endif /* defined( HAVE_CAES_TEST_MEMORY ) && defined( OPTIMIZATION_DISABLED ) */

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_XTS ) */

	/* Clean up
	 */
	result = libcaes_tweaked_context_free(
	          &tweaked_context,
	          &error );

	CAES_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	CAES_TEST_ASSERT_IS_NULL(
	 "tweaked_context",
	 tweaked_context );

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
	if( tweaked_context != NULL )
	{
		libcaes_tweaked_context_free(
		 &tweaked_context,
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
	 "libcaes_tweaked_context_initialize",
	 caes_test_tweaked_context_initialize );

	CAES_TEST_RUN(
	 "libcaes_tweaked_context_free",
	 caes_test_tweaked_context_free );

	CAES_TEST_RUN(
	 "libcaes_tweaked_context_set_keys",
	 caes_test_tweaked_context_set_keys );

	CAES_TEST_RUN(
	 "libcaes_crypt_xts",
	 caes_test_crypt_xts );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

