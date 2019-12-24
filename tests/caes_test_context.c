/*
 * Library context type test program
 *
 * Copyright (C) 2011-2019, Joachim Metz <joachim.metz@gmail.com>
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

/* Make sure libcaes_definitions.h is included first to define LIBCAES_HAVE_AES_SUPPORT
 */
#include "../libcaes/libcaes_definitions.h"
#include "../libcaes/libcaes_context.h"

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )

static int (*caes_test_real_AES_set_encrypt_key)(const unsigned char *, const int, AES_KEY *)                                                     = NULL;
static int (*caes_test_real_AES_set_decrypt_key)(const unsigned char *, const int, AES_KEY *)                                                     = NULL;

int caes_test_AES_set_encrypt_key_attempts_before_fail                                                                                            = -1;
int caes_test_AES_set_decrypt_key_attempts_before_fail                                                                                            = -1;

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )

static int (*caes_test_real_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int)                                                                    = NULL;
static int (*caes_test_real_EVP_CipherInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *, int) = NULL;
static int (*caes_test_real_EVP_CipherUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int)                               = NULL;

int caes_test_EVP_CIPHER_CTX_set_padding_attempts_before_fail                                                                                     = -1;
int caes_test_EVP_CipherInit_ex_attempts_before_fail                                                                                              = -1;
int caes_test_EVP_CipherUpdate_attempts_before_fail                                                                                               = -1;

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )

/* Custom AES_set_encrypt_key for testing error cases
 * Returns 0 if successful or a negative value otherwise
 */
int AES_set_encrypt_key(
     const unsigned char *userKey,
     const int bits,
     AES_KEY *key )
{
	int result = 0;

	if( caes_test_real_AES_set_encrypt_key == NULL )
	{
		caes_test_real_AES_set_encrypt_key = dlsym(
		                                      RTLD_NEXT,
		                                      "AES_set_encrypt_key" );
	}
	if( caes_test_AES_set_encrypt_key_attempts_before_fail == 0 )
	{
		caes_test_AES_set_encrypt_key_attempts_before_fail = -1;

		return( -1 );
	}
	else if( caes_test_AES_set_encrypt_key_attempts_before_fail > 0 )
	{
		caes_test_AES_set_encrypt_key_attempts_before_fail--;
	}
	result = caes_test_real_AES_set_encrypt_key(
	          userKey,
	          bits,
	          key );

	return( result );
}

/* Custom AES_set_decrypt_key for testing error cases
 * Returns 0 if successful or a negative value otherwise
 */
int AES_set_decrypt_key(
     const unsigned char *userKey,
     const int bits,
     AES_KEY *key )
{
	int result = 0;

	if( caes_test_real_AES_set_decrypt_key == NULL )
	{
		caes_test_real_AES_set_decrypt_key = dlsym(
		                                      RTLD_NEXT,
		                                      "AES_set_decrypt_key" );
	}
	if( caes_test_AES_set_decrypt_key_attempts_before_fail == 0 )
	{
		caes_test_AES_set_decrypt_key_attempts_before_fail = -1;

		return( -1 );
	}
	else if( caes_test_AES_set_decrypt_key_attempts_before_fail > 0 )
	{
		caes_test_AES_set_decrypt_key_attempts_before_fail--;
	}
	result = caes_test_real_AES_set_decrypt_key(
	          userKey,
	          bits,
	          key );

	return( result );
}

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )

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

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

#endif /* defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ ) */

/* Tests the libcaes_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int caes_test_context_initialize(
     void )
{
	libcaes_context_t *context      = NULL;
	libcerror_error_t *error        = NULL;
	int result                      = 0;

#if defined( HAVE_CAES_TEST_MEMORY )
	int number_of_malloc_fail_tests = 1;
	int number_of_memset_fail_tests = 1;
	int test_number                 = 0;
#endif

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

	context = NULL;

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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )
	/* No additional test definitions needed */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && !defined( HAVE_EVP_CIPHER_CTX_INIT ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )
	number_of_malloc_fail_tests = 2;

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

	/* 1 fail in memory_allocate_structure
	 * 2 fail in EVP_CIPHER_CTX_new
	 */
	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_context_initialize with malloc failing
		 */
		caes_test_malloc_attempts_before_fail = test_number;

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
	}
	/* 1 fail in memset after memory_allocate_structure
	 */
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libcaes_context_initialize with memset failing
		 */
		caes_test_memset_attempts_before_fail = test_number;

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
	}
#endif /* defined( HAVE_CAES_TEST_MEMORY ) */

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )
	/* No additional test definitions needed */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )

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

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )

#if defined( HAVE_GNU_DL_DLSYM ) && defined( __GNUC__ ) && !defined( __clang__ ) && !defined( __CYGWIN__ )

	/* Test libcaes_context_set_key with AES_set_encrypt_key failing
	 */
	caes_test_AES_set_encrypt_key_attempts_before_fail = 0;

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_ENCRYPT,
	          key,
	          128,
	          &error );

	if( caes_test_AES_set_encrypt_key_attempts_before_fail != -1 )
	{
		caes_test_AES_set_encrypt_key_attempts_before_fail = -1;
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
	/* Test libcaes_context_set_key with AES_set_decrypt_key failing
	 */
	caes_test_AES_set_decrypt_key_attempts_before_fail = 0;

	result = libcaes_context_set_key(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          key,
	          128,
	          &error );

	if( caes_test_AES_set_decrypt_key_attempts_before_fail != -1 )
	{
		caes_test_AES_set_decrypt_key_attempts_before_fail = -1;
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

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && ( defined( HAVE_EVP_CRYPTO_AES_CBC ) || defined( HAVE_EVP_CRYPTO_AES_ECB ) )

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

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

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

#if !defined( LIBCAES_HAVE_AES_SUPPORT )

#if defined( __GNUC__ ) && !defined( LIBCAES_DLL_IMPORT )

/* Tests the libcaes_initialize_tables function
 * Returns 1 if successful or 0 if not
 */
int caes_test_initialize_tables(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = libcaes_initialize_tables(
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
#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_initialize_tables with memset of logs_table failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_initialize_tables(
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libcaes_internal_context_set_decryption_key function
 * Returns 1 if successful or 0 if not
 */
int caes_test_internal_context_set_decryption_key(
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
	result = libcaes_internal_context_set_decryption_key(
	          (libcaes_internal_context_t *) context,
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
	result = libcaes_internal_context_set_decryption_key(
	          NULL,
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

	result = libcaes_internal_context_set_decryption_key(
	          (libcaes_internal_context_t *) context,
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

	result = libcaes_internal_context_set_decryption_key(
	          (libcaes_internal_context_t *) context,
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

/* Tests the libcaes_internal_context_set_encryption_key function
 * Returns 1 if successful or 0 if not
 */
int caes_test_internal_context_set_encryption_key(
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
	result = libcaes_internal_context_set_encryption_key(
	          (libcaes_internal_context_t *) context,
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
	result = libcaes_internal_context_set_encryption_key(
	          NULL,
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

	result = libcaes_internal_context_set_encryption_key(
	          (libcaes_internal_context_t *) context,
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

	result = libcaes_internal_context_set_encryption_key(
	          (libcaes_internal_context_t *) context,
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

#endif /* defined( __GNUC__ ) && !defined( LIBCAES_DLL_IMPORT ) */

#endif /* !defined( LIBCAES_HAVE_AES_SUPPORT ) */

/* Tests the libcaes_crypt_cbc function
 * Returns 1 if successful or 0 if not
 */
int caes_test_crypt_cbc(
     void )
{
	uint8_t initialization_vector[ 16 ];
	uint8_t input_data[ 208 ];
	uint8_t key[ 16 ];
	uint8_t output_data[ 208 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	size_t maximum_size        = 0;
	int result                 = 0;

	/* Initialize test
	 */
#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && defined( HAVE_AES_CBC_ENCRYPT )
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_CBC )
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
		result = libcaes_crypt_cbc(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          initialization_vector,
		          16,
		          input_data,
		          maximum_size + 1,
		          output_data,
		          208,
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
	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          8,
	          output_data,
	          208,
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
	          208,
	          NULL,
	          208,
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
		result = libcaes_crypt_cbc(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          initialization_vector,
		          16,
		          input_data,
		          208,
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
	}
	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          208,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )

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
	          208,
	          output_data,
	          208,
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

	/* Test libcaes_crypt_cbc with memset of safe_initialization_vector failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          208,
	          output_data,
	          208,
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

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_CBC )

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
	          208,
	          output_data,
	          208,
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

	/* Test libcaes_crypt_cbc with EVP_CipherInit_ex failing
	 */
	caes_test_EVP_CipherInit_ex_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          208,
	          output_data,
	          208,
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
	/* Test libcaes_crypt_cbc with EVP_CipherUpdate failing
	 */
	caes_test_EVP_CipherUpdate_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          208,
	          output_data,
	          208,
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

	/* Test libcaes_crypt_cbc with memcpy of initialization_vector to internal_initialization_vector failing
	 */
	caes_test_memcpy_attempts_before_fail = 0;

	result = libcaes_crypt_cbc(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          16,
	          input_data,
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

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
	uint8_t input_data[ 208 ];
	uint8_t key[ 16 ];
	uint8_t nonce[ 8 ];
	uint8_t output_data[ 208 ];

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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          8,
	          input_data,
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
	          output_data,
	          208,
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
	          208,
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
	          208,
	          NULL,
	          208,
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
	          208,
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
		          208,
		          output_data,
		          208,
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
		          208,
		          output_data,
		          208,
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

/* Tests the libcaes_crypt_ecb function
 * Returns 1 if successful or 0 if not
 */
int caes_test_crypt_ecb(
     void )
{
	uint8_t input_data[ 208 ];
	uint8_t key[ 16 ];
	uint8_t output_data[ 208 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	size_t maximum_size        = 0;
	int result                 = 0;

	/* Initialize test
	 */
#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_ECB )
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
	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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
	result = libcaes_crypt_ecb(
	          NULL,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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

	result = libcaes_crypt_ecb(
	          context,
	          -1,
	          input_data,
	          208,
	          output_data,
	          208,
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

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          NULL,
	          208,
	          output_data,
	          208,
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
		result = libcaes_crypt_ecb(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          input_data,
		          (size_t) maximum_size + 1,
		          output_data,
		          208,
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
	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          0,
	          output_data,
	          208,
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

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          NULL,
	          208,
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
		result = libcaes_crypt_ecb(
		          context,
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          input_data,
		          208,
		          output_data,
		          (size_t) maximum_size + 1,
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
	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) )
	/* No additional test definitions needed */

#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_ECB )

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_ecb with memset of block_data failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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

	/* Test libcaes_crypt_ecb with EVP_CipherInit_ex failing
	 */
	caes_test_EVP_CipherInit_ex_attempts_before_fail = 0;

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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
	/* Test libcaes_crypt_ecb with EVP_CipherUpdate failing
	 */
	caes_test_EVP_CipherUpdate_attempts_before_fail = 0;

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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

#if defined( HAVE_CAES_TEST_MEMORY )

	/* Test libcaes_crypt_ecb with memset of values_32bit failing
	 */
	caes_test_memset_attempts_before_fail = 0;

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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
	/* Test libcaes_crypt_ecb with memset of cipher_values_32bit failing
	 */
	caes_test_memset_attempts_before_fail = 1;

	result = libcaes_crypt_ecb(
	          context,
	          LIBCAES_CRYPT_MODE_DECRYPT,
	          input_data,
	          208,
	          output_data,
	          208,
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

#endif /* defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && ( defined( HAVE_AES_CBC_ENCRYPT ) || defined( HAVE_AES_EBC_ENCRYPT ) ) */

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

#if defined( __GNUC__ ) && !defined( LIBCAES_DLL_IMPORT )

	CAES_TEST_RUN(
	 "libcaes_initialize_tables",
	 caes_test_initialize_tables );

	CAES_TEST_RUN(
	 "libcaes_internal_context_set_decryption_key",
	 caes_test_internal_context_set_decryption_key );

	CAES_TEST_RUN(
	 "libcaes_internal_context_set_encryption_key",
	 caes_test_internal_context_set_encryption_key );

#endif /* defined( __GNUC__ ) && !defined( LIBCAES_DLL_IMPORT ) */

#endif /* !defined( LIBCAES_HAVE_AES_SUPPORT ) */

	CAES_TEST_RUN(
	 "libcaes_crypt_cbc",
	 caes_test_crypt_cbc );

	CAES_TEST_RUN(
	 "libcaes_crypt_ccm",
	 caes_test_crypt_ccm );

	/* TODO: add tests for libcaes_crypt_cfb */

	CAES_TEST_RUN(
	 "libcaes_crypt_ecb",
	 caes_test_crypt_ecb );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

