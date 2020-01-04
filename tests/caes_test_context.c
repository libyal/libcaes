/*
 * Library context type test program
 *
 * Copyright (C) 2011-2020, Joachim Metz <joachim.metz@gmail.com>
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
#include <memory.h>
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

typedef struct caes_test_context_test_vector caes_test_context_test_vector_t;

struct caes_test_context_test_vector
{
	/* The description
	 */
	const char *description;

	/* The mode
	 */
	int mode;

	/* The key
	 */
	uint8_t key[ 64 ];

	/* The key bit size
	 */
	size_t key_bit_size;

	/* The initialization vector
	 */
	uint8_t initialization_vector[ 16 ];

	/* The initialization vector size
	 */
	size_t initialization_vector_size;

	/* The input data
	 */
	uint8_t input_data[ 16 ];

	/* The input data size
	 */
	size_t input_data_size;

	/* The expected output data
	 */
	uint8_t output_data[ 16 ];

	/* The expected output data size
	 */
	size_t output_data_size;
};

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
	uint8_t output_data[ 16 ];

	caes_test_context_test_vector_t test_vectors[ 24 ] = {
		{ "NIST SP800-38A test vector AES-CBC 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d }, 16,
		  { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 }, 16,
		  { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 }, 16,
		  { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },

		{ "NIST SP800-38A test vector AES-CBC 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8 }, 16,
		  { 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a }, 16,
		  { 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62,
		    0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0 }, 16,
		  { 0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },

		{ "NIST SP800-38A test vector AES-CBC 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 16,
		  { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 }, 16,
		  { 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61 }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d }, 16,
		  { 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b }, 16 },
		{ "NIST SP800-38A test vector AES-CBC 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61 }, 16,
		  { 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },
	};

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	size_t maximum_size        = 0;
	int result                 = 0;
	int test_number            = 0;

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
	for( test_number = 0;
	     test_number < 24;
	     test_number++ )
	{
		result = libcaes_context_set_key(
		          context,
		          test_vectors[ test_number ].mode,
		          test_vectors[ test_number ].key,
		          test_vectors[ test_number ].key_bit_size,
		          &error );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		CAES_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		result = libcaes_crypt_cbc(
		          context,
		          test_vectors[ test_number ].mode,
		          test_vectors[ test_number ].initialization_vector,
		          test_vectors[ test_number ].initialization_vector_size,
		          test_vectors[ test_number ].input_data,
		          test_vectors[ test_number ].input_data_size,
		          output_data,
		          test_vectors[ test_number ].output_data_size,
		          &error );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		CAES_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		result = memory_compare(
		          output_data,
		          test_vectors[ test_number ].output_data,
		          test_vectors[ test_number ].output_data_size );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 0 );
	}
	/* Test error cases
	 */
	result = libcaes_crypt_cbc(
	          NULL,
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          NULL,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          0,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          NULL,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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

#if defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_AES_H ) && defined( HAVE_AES_CBC_ENCRYPT )
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_CBC )
	maximum_size = (size_t) INT_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

	if( maximum_size > 0 )
	{
		result = libcaes_crypt_cbc(
		          context,
		          test_vectors[ 1 ].mode,
		          test_vectors[ 1 ].initialization_vector,
		          test_vectors[ 1 ].initialization_vector_size,
		          test_vectors[ 1 ].input_data,
		          maximum_size + 1,
		          output_data,
		          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          8,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          NULL,
	          test_vectors[ 1 ].output_data_size,
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
		          test_vectors[ 1 ].mode,
		          test_vectors[ 1 ].initialization_vector,
		          test_vectors[ 1 ].initialization_vector_size,
		          test_vectors[ 1 ].input_data,
		          test_vectors[ 1 ].input_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 0 ].mode,
	          test_vectors[ 0 ].initialization_vector,
	          test_vectors[ 0 ].initialization_vector_size,
	          test_vectors[ 0 ].input_data,
	          test_vectors[ 0 ].input_data_size,
	          output_data,
	          test_vectors[ 0 ].output_data_size,
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
	          test_vectors[ 0 ].mode,
	          test_vectors[ 0 ].initialization_vector,
	          test_vectors[ 0 ].initialization_vector_size,
	          test_vectors[ 0 ].input_data,
	          test_vectors[ 0 ].input_data_size,
	          output_data,
	          test_vectors[ 0 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].initialization_vector,
	          test_vectors[ 1 ].initialization_vector_size,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	uint8_t output_data[ 16 ];

	caes_test_context_test_vector_t test_vectors[ 30 ] = {
		{ "FIPS-197 test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16,
		  { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }, 16 },
		{ "FIPS-197 test vector 1 AES-ECB 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16 },
		{ "FIPS-197 test vector 2 AES-ECB 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16,
		  { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }, 16 },
		{ "FIPS-197 test vector 2 AES-ECB 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16 },
		{ "FIPS-197 test vector 2 AES-ECB 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16,
		  { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }, 16 },
		{ "FIPS-197 test vector 2 AES-ECB 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }, 16,
		  { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 16 },

		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 128-bit encrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }, 128,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },

		{ "NIST SP800-38A test vector AES-ECB 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad, 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad, 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a, 0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a, 0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72, 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 192-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b }, 192,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72, 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },

		{ "NIST SP800-38A test vector AES-ECB 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16,
		  { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 }, 16,
		  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16,
		  { 0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70 }, 16,
		  { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16,
		  { 0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d }, 16,
		  { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit encrypt", LIBCAES_CRYPT_MODE_ENCRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16,
		  { 0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 }, 16 },
		{ "NIST SP800-38A test vector AES-ECB 256-bit decrypt", LIBCAES_CRYPT_MODE_DECRYPT,
		  { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }, 256,
		  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 16,
		  { 0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 }, 16,
		  { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }, 16 },
	};

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	size_t maximum_size        = 0;
	int result                 = 0;
	int test_number            = 0;

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
	for( test_number = 0;
	     test_number < 30;
	     test_number++ )
	{
		result = libcaes_context_set_key(
		          context,
		          test_vectors[ test_number ].mode,
		          test_vectors[ test_number ].key,
		          test_vectors[ test_number ].key_bit_size,
		          &error );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		CAES_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		result = libcaes_crypt_ecb(
		          context,
		          test_vectors[ test_number ].mode,
		          test_vectors[ test_number ].input_data,
		          test_vectors[ test_number ].input_data_size,
		          output_data,
		          test_vectors[ test_number ].output_data_size,
		          &error );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		CAES_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		result = memory_compare(
		          output_data,
		          test_vectors[ test_number ].output_data,
		          test_vectors[ test_number ].output_data_size );

		CAES_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 0 );
	}
	/* Test error cases
	 */
	result = libcaes_crypt_ecb(
	          NULL,
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          NULL,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	maximum_size = (size_t) SSIZE_MAX;
#elif defined( HAVE_LIBCRYPTO ) && defined( HAVE_OPENSSL_EVP_H ) && defined( HAVE_EVP_CRYPTO_AES_ECB )
	maximum_size = (size_t) INT_MAX;
#else
	maximum_size = (size_t) SSIZE_MAX;
#endif

	if( maximum_size > 0 )
	{
		result = libcaes_crypt_ecb(
		          context,
		          test_vectors[ 1 ].mode,
		          test_vectors[ 1 ].input_data,
		          (size_t) maximum_size + 1,
		          output_data,
		          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          0,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          NULL,
	          test_vectors[ 1 ].output_data_size,
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
		          test_vectors[ 1 ].mode,
		          test_vectors[ 1 ].input_data,
		          test_vectors[ 1 ].input_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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
	          test_vectors[ 1 ].mode,
	          test_vectors[ 1 ].input_data,
	          test_vectors[ 1 ].input_data_size,
	          output_data,
	          test_vectors[ 1 ].output_data_size,
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

