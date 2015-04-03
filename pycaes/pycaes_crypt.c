/*
 * Python definition of the libcaes crypt functions
 *
 * Copyright (C) 2010-2015, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pycaes_context.h"
#include "pycaes_crypt.h"
#include "pycaes_error.h"
#include "pycaes_libcaes.h"
#include "pycaes_python.h"
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
/* TODO output data */
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
		 "%s: unable to set key.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

