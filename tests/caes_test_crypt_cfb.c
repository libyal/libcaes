/*
 * Library AES-CFB de/encryption testing program
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

#include <stdio.h>

#include "caes_test_libcaes.h"
#include "caes_test_libcerror.h"
#include "caes_test_unused.h"

/* Tests AES-CFB de/encryption
 * Returns 1 if successful, 0 if not or -1 on error
 */
int caes_test_crypt_cfb(
     int mode,
     const uint8_t *key,
     size_t key_bit_size,
     const uint8_t *initialization_vector,
     size_t initialization_vector_size,
     const uint8_t *input_data,
     size_t input_data_size,
     const uint8_t *expected_output_data,
     size_t expected_output_data_size )
{
	uint8_t output_data[ 32 ];

	libcaes_context_t *context = NULL;
	libcerror_error_t *error   = NULL;
	static char *function      = "caes_test_crypt_cfb";
	size_t output_data_size    = 32;
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
	     mode,
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
/* TODO
	if( libcaes_crypt_cfb(
	     context,
	     mode,
	     initialization_vector,
	     initialization_vector_size,
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
*/
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
	/* Values from NIST KAT-AES CFBVarKey128.rsp, CFBVarKey192.rsp and CFBVarKey256.rsp */
	uint8_t keys[ 256 ][ 32 ];

	/* Values from NIST KAT-AES CFBVarTxt128.rsp */
	uint8_t cipher_texts1_128bit[ 128 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarKey128.rsp */
	uint8_t cipher_texts2_128bit[ 128 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarTxt192.rsp */
	uint8_t cipher_texts1_192bit[ 128 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarKey192.rsp */
	uint8_t cipher_texts2_192bit[ 192 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarTxt256.rsp */
	uint8_t cipher_texts1_256bit[ 128 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarKey256.rsp */
	uint8_t cipher_texts2_256bit[ 256 ][ 16 ];

	/* Values from NIST KAT-AES CFBVarTxt128.rsp, CFBVarTxt192.rsp and CFBVarTxt256.rsp */
	uint8_t plain_texts1[ 128 ][ 16 ];

	uint8_t key[ 32 ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	uint8_t initialization_vector[ 16 ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	uint8_t plain_text[ 16 ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	int result     = 0;
	int test_index = 0;

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
	 "Testing AES-CFB 128-bit decryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          key,
		          128,
		          initialization_vector,
		          16,
		          cipher_texts1_128bit[ test_index ],
		          16,
		          plain_texts1[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 128-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 128-bit decryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          keys[ test_index ],
		          128,
		          initialization_vector,
		          16,
		          cipher_texts2_128bit[ test_index ],
		          16,
		          plain_text,
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 128-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 192-bit decryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          key,
		          192,
		          initialization_vector,
		          16,
		          cipher_texts1_192bit[ test_index ],
		          16,
		          plain_texts1[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 192-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 192-bit decryption\t" );

	for( test_index = 0;
	     test_index < 192;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          keys[ test_index ],
		          192,
		          initialization_vector,
		          16,
		          cipher_texts2_192bit[ test_index ],
		          16,
		          plain_text,
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 192-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 256-bit decryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          key,
		          256,
		          initialization_vector,
		          16,
		          cipher_texts1_256bit[ test_index ],
		          16,
		          plain_texts1[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 256-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 256-bit decryption\t" );

	for( test_index = 0;
	     test_index < 256;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_DECRYPT,
		          keys[ test_index ],
		          256,
		          initialization_vector,
		          16,
		          cipher_texts2_256bit[ test_index ],
		          16,
		          plain_text,
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 256-bit decryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	 "Testing AES-CFB 128-bit encryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          key,
		          128,
		          initialization_vector,
		          16,
		          plain_texts1[ test_index ],
		          16,
		          cipher_texts1_128bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 128-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 128-bit encryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          keys[ test_index ],
		          128,
		          initialization_vector,
		          16,
		          plain_text,
		          16,
		          cipher_texts2_128bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 128-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 192-bit encryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          key,
		          192,
		          initialization_vector,
		          16,
		          plain_texts1[ test_index ],
		          16,
		          cipher_texts1_192bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 192-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 192-bit encryption\t" );

	for( test_index = 0;
	     test_index < 192;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          keys[ test_index ],
		          192,
		          initialization_vector,
		          16,
		          plain_text,
		          16,
		          cipher_texts2_192bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 192-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 256-bit encryption\t" );

	for( test_index = 0;
	     test_index < 128;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          key,
		          256,
		          initialization_vector,
		          16,
		          plain_texts1[ test_index ],
		          16,
		          cipher_texts1_256bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 256-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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
	fprintf(
	 stdout,
	 "Testing AES-CFB 256-bit encryption\t" );

	for( test_index = 0;
	     test_index < 256;
	     test_index++ )
	{
		result = caes_test_crypt_cfb(
		          LIBCAES_CRYPT_MODE_ENCRYPT,
		          keys[ test_index ],
		          256,
		          initialization_vector,
		          16,
		          plain_text,
		          16,
		          cipher_texts2_256bit[ test_index ],
		          16 );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to test AES-CFB 256-bit encryption.\n" );

			return( EXIT_FAILURE );
		}
		else if( result != 1 )
		{
			break;
		}
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

