/*
 * Python definition of the libcaes crypt functions
 *
 * Copyright (C) 2010-2022, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pycaes_context.h"
#include "pycaes_crypt.h"
#include "pycaes_error.h"
#include "pycaes_libcaes.h"
#include "pycaes_python.h"
#include "pycaes_tweaked_context.h"
#include "pycaes_unused.h"

/* De- or encrypts a block of data using AES-CBC (Cipher Block Chaining)
 * The size of the data must be a multitude of the AES block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
PyObject *pycaes_crypt_cbc(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error                      = NULL;
	pycaes_context_t *pycaes_context              = NULL;
	PyObject *context_object                      = NULL;
	PyObject *initialization_vector_string_object = NULL;
	PyObject *input_data_string_object            = NULL;
	PyObject *output_data_string_object           = NULL;
	static char *function                         = "pycaes_crypt_cbc";
	static char *keyword_list[]                   = { "context", "mode", "initialization_vector", "data", NULL };
	char *initialization_vector_data              = NULL;
	char *input_data                              = NULL;
	char *output_data                             = NULL;
        Py_ssize_t initialization_vector_data_size    = 0;
        Py_ssize_t input_data_size                    = 0;
	int mode                                      = 0;
	int result                                    = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiOO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &initialization_vector_string_object,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pycaes_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pycaes_context = (pycaes_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	initialization_vector_data = PyBytes_AsString(
	                              initialization_vector_string_object );

	initialization_vector_data_size = PyBytes_Size(
	                                   initialization_vector_string_object );
#else
	initialization_vector_data = PyString_AsString(
	                              initialization_vector_string_object );

	initialization_vector_data_size = PyString_Size(
	                                   initialization_vector_string_object );
#endif
	if( ( initialization_vector_data_size < 0 )
	 || ( initialization_vector_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument initialization vector data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_crypt_cbc(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) initialization_vector_data,
	          (size_t) initialization_vector_data_size,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

/* De- or encrypts a block of data using AES-CCM (Counter with CBC-MAC)
 * Note that the key must be set in encryption mode (LIBCAES_CRYPT_MODE_ENCRYPT) for both de- and encryption.
 * Returns 1 if successful or -1 on error
 */
PyObject *pycaes_crypt_ccm(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error            = NULL;
	pycaes_context_t *pycaes_context    = NULL;
	PyObject *context_object            = NULL;
	PyObject *nonce_string_object       = NULL;
	PyObject *input_data_string_object  = NULL;
	PyObject *output_data_string_object = NULL;
	static char *function               = "pycaes_crypt_ccm";
	static char *keyword_list[]         = { "context", "mode", "nonce", "data", NULL };
	char *nonce_data                    = NULL;
	char *input_data                    = NULL;
	char *output_data                   = NULL;
        Py_ssize_t nonce_data_size          = 0;
        Py_ssize_t input_data_size          = 0;
	int mode                            = 0;
	int result                          = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiOO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &nonce_string_object,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pycaes_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pycaes_context = (pycaes_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	nonce_data = PyBytes_AsString(
	              nonce_string_object );

	nonce_data_size = PyBytes_Size(
	                   nonce_string_object );
#else
	nonce_data = PyString_AsString(
	              nonce_string_object );

	nonce_data_size = PyString_Size(
	                   nonce_string_object );
#endif
	if( ( nonce_data_size < 0 )
	 || ( nonce_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument nonce data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_crypt_ccm(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) nonce_data,
	          (size_t) nonce_data_size,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

#ifdef TODO

/* De- or encrypts a block of data using AES-CFB (Cipher Feedback Mode)
 * Returns 1 if successful or -1 on error
 */
PyObject *pycaes_crypt_cfb(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error                      = NULL;
	pycaes_context_t *pycaes_context              = NULL;
	PyObject *context_object                      = NULL;
	PyObject *initialization_vector_string_object = NULL;
	PyObject *input_data_string_object            = NULL;
	PyObject *output_data_string_object           = NULL;
	static char *function                         = "pycaes_crypt_cfb";
	static char *keyword_list[]                   = { "context", "mode", "initialization_vector", "data", NULL };
	char *initialization_vector_data              = NULL;
	char *input_data                              = NULL;
	char *output_data                             = NULL;
        Py_ssize_t initialization_vector_data_size    = 0;
        Py_ssize_t input_data_size                    = 0;
	int mode                                      = 0;
	int result                                    = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiOO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &initialization_vector_string_object,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pycaes_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pycaes_context = (pycaes_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	initialization_vector_data = PyBytes_AsString(
	                              initialization_vector_string_object );

	initialization_vector_data_size = PyBytes_Size(
	                                   initialization_vector_string_object );
#else
	initialization_vector_data = PyString_AsString(
	                              initialization_vector_string_object );

	initialization_vector_data_size = PyString_Size(
	                                   initialization_vector_string_object );
#endif
	if( ( initialization_vector_data_size < 0 )
	 || ( initialization_vector_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument initialization vector data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_crypt_cfb(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) initialization_vector_data,
	          (size_t) initialization_vector_data_size,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}
#endif /* TODO */

/* De- or encrypts a block of data using AES-ECB (Electronic CodeBook)
 * The size of the data must be a multitude of the AES block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
PyObject *pycaes_crypt_ecb(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error            = NULL;
	pycaes_context_t *pycaes_context    = NULL;
	PyObject *context_object            = NULL;
	PyObject *input_data_string_object  = NULL;
	PyObject *output_data_string_object = NULL;
	static char *function               = "pycaes_crypt_ecb";
	static char *keyword_list[]         = { "context", "mode", "data", NULL };
	char *input_data                    = NULL;
	char *output_data                   = NULL;
        Py_ssize_t input_data_size          = 0;
	int mode                            = 0;
	int result                          = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pycaes_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pycaes_context = (pycaes_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_crypt_ecb(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

/* De- or encrypts a block of data using AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing)
 * Returns 1 if successful or -1 on error
 */
PyObject *pycaes_crypt_xts(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error                 = NULL;
	pycaes_tweaked_context_t *pycaes_context = NULL;
	PyObject *context_object                 = NULL;
	PyObject *tweak_value_string_object      = NULL;
	PyObject *input_data_string_object       = NULL;
	PyObject *output_data_string_object      = NULL;
	static char *function                    = "pycaes_crypt_xts";
	static char *keyword_list[]              = { "context", "mode", "tweak_value", "data", NULL };
	char *tweak_value_data                   = NULL;
	char *input_data                         = NULL;
	char *output_data                        = NULL;
        Py_ssize_t tweak_value_data_size         = 0;
        Py_ssize_t input_data_size               = 0;
	int mode                                 = 0;
	int result                               = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiOO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &tweak_value_string_object,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pycaes_tweaked_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pycaes_context = (pycaes_tweaked_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	tweak_value_data = PyBytes_AsString(
	                    tweak_value_string_object );

	tweak_value_data_size = PyBytes_Size(
	                         tweak_value_string_object );
#else
	tweak_value_data = PyString_AsString(
	                    tweak_value_string_object );

	tweak_value_data_size = PyString_Size(
	                         tweak_value_string_object );
#endif
	if( ( tweak_value_data_size < 0 )
	 || ( tweak_value_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument tweak value data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_crypt_xts(
	          pycaes_context->tweaked_context,
	          mode,
	          (uint8_t *) tweak_value_data,
	          (size_t) tweak_value_data_size,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

