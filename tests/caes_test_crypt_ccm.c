/*
 * Library AES-CCM de/encryption testing program
 *
 * Copyright (C) 2011-2019, Joachim Metz <joachim.metz@gmail.com>
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
#include <memory.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "caes_test_libcaes.h"
#include "caes_test_libcerror.h"
#include "caes_test_unused.h"

/* Tests AES-CCM de/encryption
 * Returns 1 if successful, 0 if not or -1 on error
 */
int caes_test_crypt_ccm(
     int mode,
     const uint8_t *key,
     size_t key_bit_size,
     const uint8_t *nonce,
     size_t nonce_size,
     const uint8_t *input_data,
     size_t input_data_size,
     const uint8_t *expected_output_data,
     size_t expected_output_data_size )
{
	uint8_t output_data[ 256 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	static char *function      = "caes_test_crypt_ccm";
	size_t output_data_size    = 256;
	int result                 = 0;

	if( input_data_size > output_data_size )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid input data size value out of bounds.",
		 function );

		goto on_error;
	}
	if( libcaes_context_initialize(
	     &context,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create context.",
		 function );

		goto on_error;
	}
	if( libcaes_context_set_key(
	     context,
	     LIBCAES_CRYPT_MODE_ENCRYPT,
	     key,
	     key_bit_size,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to set key in context.",
		 function );

		goto on_error;
	}
	if( libcaes_crypt_ccm(
	     context,
	     mode,
	     nonce,
	     nonce_size,
	     input_data,
	     input_data_size,
	     output_data,
	     output_data_size,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
		 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
		 "%s: unable to de/encrypt data.",
		 function );

		goto on_error;
	}
	result = memory_compare(
	          output_data,
	          expected_output_data,
	          expected_output_data_size );

	if( libcaes_context_free(
	     &context,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free context.",
		 function );

		goto on_error;
	}
	if( result != 0 )
	{
		return( 0 );
	}
	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_backtrace_fprint(
		 error,
		 stdout );

		libcerror_error_free(
		 &error );
	}
	if( context != NULL )
	{
		libcaes_context_free(
		 &context,
		 NULL );
	}
	return( -1 );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] CAES_TEST_ATTRIBUTE_UNUSED )
#else
int main( int argc, char * const argv[] CAES_TEST_ATTRIBUTE_UNUSED )
#endif
{
	uint8_t key[ 32 ] = {
		0x8a, 0x29, 0x41, 0xff, 0x7b, 0x3a, 0x5e, 0xe9, 0x0b, 0xca, 0x70, 0xfb, 0xb2, 0x65, 0xaf, 0xab,
		0xed, 0x68, 0xb1, 0x55, 0x07, 0x65, 0x25, 0x55, 0x40, 0xc8, 0x86, 0x1e, 0x13, 0x7e, 0xd0, 0x94 };

	uint8_t nonce[ 12 ] = {
		0x60, 0xd5, 0x17, 0x86, 0x5b, 0x53, 0xcc, 0x01, 0x03, 0x00, 0x00, 0x00 };

	uint8_t cipher_text[ 60 ] = {
		0xa8, 0xdf, 0x3d, 0x7c, 0x99, 0x74, 0x2c, 0x49, 0x68, 0x85, 0x70, 0x84, 0x6a, 0xd5, 0xf8, 0x0c,
		0x6b, 0x66, 0xc6, 0x8a, 0x3e, 0x30, 0xb7, 0x5b, 0xed, 0x61, 0x52, 0x9c, 0x73, 0xce, 0x36, 0x5c,
		0xa1, 0x96, 0x0e, 0x91, 0xa1, 0x48, 0x83, 0x67, 0x8d, 0x09, 0x41, 0xde, 0x51, 0x0b, 0x04, 0x49,
		0xa4, 0x19, 0xb5, 0x1e, 0x49, 0xd2, 0xac, 0xfd, 0x6a, 0x0a, 0x78, 0x8c };

	uint8_t plain_text[ 60 ] = {
		0x18, 0x27, 0x1c, 0x74, 0xeb, 0x49, 0x16, 0xbf, 0x6b, 0x46, 0x31, 0x74, 0x15, 0x41, 0xf1, 0x99,
		0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x68, 0x8a, 0x51, 0x70,
		0x06, 0x14, 0xdb, 0xd1, 0xc1, 0x00, 0xf5, 0x68, 0xc4, 0xbd, 0x29, 0xa6, 0x3c, 0x46, 0x36, 0x72,
		0xbe, 0x6b, 0xde, 0xf5, 0x4b, 0x91, 0x8b, 0xb9, 0xa3, 0xa4, 0x3c, 0xbc };

	int result = 0;

	CAES_TEST_UNREFERENCED_PARAMETER( argv )

	if( argc != 1 )
	{
		fprintf(
		 stderr,
		 "Unsupported number of arguments.\n" );

		return( EXIT_FAILURE );
	}
	/* Decryption tests
	 */
	fprintf(
	 stdout,
	 "Testing AES-CCM 256-bit decryption\t" );

	result = caes_test_crypt_ccm(
		  LIBCAES_CRYPT_MODE_DECRYPT,
		  key,
		  256,
		  nonce,
		  12,
		  cipher_text,
		  60,
		  plain_text,
		  60 );

	if( result == -1 )
	{
		fprintf(
		 stderr,
		 "Unable to test AES-CCM 256-bit decryption.\n" );

		return( EXIT_FAILURE );
	}
	if( result != 1 )
	{
		fprintf(
		 stdout,
		 "(FAIL)" );
	}
	else
	{
		fprintf(
		 stdout,
		 "(PASS)" );
	}
	fprintf(
	 stdout,
	 "\n" );

	if( result != 1 )
	{
		return( EXIT_FAILURE );
	}
	/* Encryption tests
	 */
	fprintf(
	 stdout,
	 "Testing AES-CCM 256-bit encryption\t" );

	result = caes_test_crypt_ccm(
		  LIBCAES_CRYPT_MODE_ENCRYPT,
		  key,
		  256,
		  nonce,
		  12,
		  plain_text,
		  60,
		  cipher_text,
		  60 );

	if( result == -1 )
	{
		fprintf(
		 stderr,
		 "Unable to test AES-CCM 256-bit encryption.\n" );

		return( EXIT_FAILURE );
	}
	if( result != 1 )
	{
		fprintf(
		 stdout,
		 "(FAIL)" );
	}
	else
	{
		fprintf(
		 stdout,
		 "(PASS)" );
	}
	fprintf(
	 stdout,
	 "\n" );

	if( result != 1 )
	{
		return( EXIT_FAILURE );
	}
	return( EXIT_SUCCESS );
}

