/*
 * Python object definition of the libcaes tweaked context
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pycaes_error.h"
#include "pycaes_libcaes.h"
#include "pycaes_libcerror.h"
#include "pycaes_libcstring.h"
#include "pycaes_python.h"
#include "pycaes_tweaked_context.h"
#include "pycaes_unused.h"

PyMethodDef pycaes_tweaked_context_object_methods[] = {

	{ "set_keys",
	  (PyCFunction) pycaes_tweaked_context_set_keys,
	  METH_VARARGS | METH_KEYWORDS,
	  "set_keys(mode, key, tweak_key) -> None\n"
	  "\n"
	  "Sets the key and tweak key for a specific crypt mode" },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pycaes_tweaked_context_object_get_set_definitions[] = {

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pycaes_tweaked_context_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pycaes.tweaked_context",
	/* tp_basicsize */
	sizeof( pycaes_tweaked_context_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pycaes_tweaked_context_free,
	/* tp_print */
	0,
	/* tp_getattr */
	0,
	/* tp_setattr */
	0,
	/* tp_compare */
	0,
	/* tp_repr */
	0,
	/* tp_as_number */
	0,
	/* tp_as_sequence */
	0,
	/* tp_as_mapping */
	0,
	/* tp_hash */
	0,
	/* tp_call */
	0,
	/* tp_str */
	0,
	/* tp_getattro */
	0,
	/* tp_setattro */
	0,
	/* tp_as_buffer */
	0,
	/* tp_flags */
	Py_TPFLAGS_DEFAULT,
	/* tp_doc */
	"pycaes tweaked context object (wraps libcaes_tweaked_context_t)",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	0,
	/* tp_iternext */
	0,
	/* tp_methods */
	pycaes_tweaked_context_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pycaes_tweaked_context_object_get_set_definitions,
	/* tp_base */
	0,
	/* tp_dict */
	0,
	/* tp_descr_get */
	0,
	/* tp_descr_set */
	0,
	/* tp_dictoffset */
	0,
	/* tp_init */
	(initproc) pycaes_tweaked_context_init,
	/* tp_alloc */
	0,
	/* tp_new */
	0,
	/* tp_free */
	0,
	/* tp_is_gc */
	0,
	/* tp_bases */
	NULL,
	/* tp_mro */
	NULL,
	/* tp_cache */
	NULL,
	/* tp_subclasses */
	NULL,
	/* tp_weaklist */
	NULL,
	/* tp_del */
	0
};

/* Creates a new tweaked context object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pycaes_tweaked_context_new(
           void )
{
	pycaes_tweaked_context_t *pycaes_context = NULL;
	static char *function                    = "pycaes_tweaked_context_new";

	pycaes_context = PyObject_New(
	                  struct pycaes_tweaked_context,
	                  &pycaes_tweaked_context_type_object );
   
	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize tweaked context.",
		 function );

		goto on_error;
	}
	if( pycaes_tweaked_context_init(
	     pycaes_context ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize tweaked context.",
		 function );

		goto on_error;
	}
	return( (PyObject *) pycaes_context );

on_error:
	if( pycaes_context != NULL )
	{
		Py_DecRef(
		 (PyObject *) pycaes_context );
	}
	return( NULL );
}

/* Intializes a tweaked context object
 * Returns 0 if successful or -1 on error
 */
int pycaes_tweaked_context_init(
     pycaes_tweaked_context_t *pycaes_context )
{
	static char *function    = "pycaes_tweaked_context_init";
	libcerror_error_t *error = NULL;

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid tweaked context.",
		 function );

		return( -1 );
	}
	pycaes_context->context = NULL;

	if( libcaes_tweaked_context_initialize(
	     &( pycaes_context->context ),
	     &error ) != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize tweaked context.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a tweaked context object
 */
void pycaes_tweaked_context_free(
      pycaes_tweaked_context_t *pycaes_context )
{
	libcerror_error_t *error    = NULL;
	struct _typeobject *ob_type = NULL;
	static char *function       = "pycaes_tweaked_context_free";
	int result                  = 0;

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid tweaked context.",
		 function );

		return;
	}
	if( pycaes_context->context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid tweaked context - missing libcaes context.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pycaes_context );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_tweaked_context_free(
	          &( pycaes_context->context ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libcaes tweaked context.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pycaes_context );
}

/* Sets the keys
 * Returns a Python object if successful or NULL on error
 */
PyObject *pycaes_tweaked_context_set_keys(
           pycaes_tweaked_context_t *pycaes_context,
           PyObject *arguments,
           PyObject *keywords )
{
	libcerror_error_t *error          = NULL;
	PyObject *key_string_object       = NULL;
	PyObject *tweak_key_string_object = NULL;
	static char *function             = "pycaes_tweaked_context_set_key";
	static char *keyword_list[]       = { "mode", "key", "tweak_key", NULL };
	char *key_data                    = NULL;
	char *tweak_key_data              = NULL;
        Py_ssize_t key_data_size          = 0;
        Py_ssize_t tweak_key_data_size    = 0;
	int mode                          = 0;
	int result                        = 0;

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "iOO",
	     keyword_list,
	     &mode,
	     &key_string_object,
	     &tweak_key_string_object ) == 0 )
	{
		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	key_data = PyBytes_AsString(
	            key_string_object );

	key_data_size = PyBytes_Size(
	                 key_string_object );
#else
	key_data = PyString_AsString(
	            key_string_object );

	key_data_size = PyString_Size(
	                 key_string_object );
#endif
	if( ( key_data_size < 0 )
	 || ( key_data_size > (Py_ssize_t) ( SSIZE_MAX / 8 ) ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument key data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	tweak_key_data = PyBytes_AsString(
	                  tweak_key_string_object );

	tweak_key_data_size = PyBytes_Size(
	                       tweak_key_string_object );
#else
	tweak_key_data = PyString_AsString(
	                  tweak_key_string_object );

	tweak_key_data_size = PyString_Size(
	                       tweak_key_string_object );
#endif
	if( ( tweak_key_data_size < 0 )
	 || ( tweak_key_data_size > (Py_ssize_t) ( SSIZE_MAX / 8 ) ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument tweak key data size value out of bounds.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_tweaked_context_set_keys(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) key_data,
	          (size_t) ( key_data_size * 8 ),
	          (uint8_t *) tweak_key_data,
	          (size_t) ( tweak_key_data_size * 8 ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to set keys.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

