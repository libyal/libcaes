/*
 * Python object wrapper of libcaes_context_t
 *
 * Copyright (C) 2011-2025, Joachim Metz <joachim.metz@gmail.com>
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
#include "pycaes_error.h"
#include "pycaes_libcaes.h"
#include "pycaes_libcerror.h"
#include "pycaes_python.h"
#include "pycaes_unused.h"

PyMethodDef pycaes_context_object_methods[] = {

	{ "set_key",
	  (PyCFunction) pycaes_context_set_key,
	  METH_VARARGS | METH_KEYWORDS,
	  "set_key(mode, key) -> None\n"
	  "\n"
	  "Sets the key for a specific crypt mode." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pycaes_context_object_get_set_definitions[] = {

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pycaes_context_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pycaes.context",
	/* tp_basicsize */
	sizeof( pycaes_context_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pycaes_context_free,
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
	"pycaes context object (wraps libcaes_context_t)",
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
	pycaes_context_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pycaes_context_object_get_set_definitions,
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
	(initproc) pycaes_context_init,
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

/* Creates a new context object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pycaes_context_new(
           void )
{
	pycaes_context_t *pycaes_context = NULL;
	static char *function            = "pycaes_context_new";

	pycaes_context = PyObject_New(
	                  struct pycaes_context,
	                  &pycaes_context_type_object );

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize context.",
		 function );

		goto on_error;
	}
	if( pycaes_context_init(
	     pycaes_context ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize context.",
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

/* Initializes a context object
 * Returns 0 if successful or -1 on error
 */
int pycaes_context_init(
     pycaes_context_t *pycaes_context )
{
	libcerror_error_t *error = NULL;
	static char *function    = "pycaes_context_init";

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	pycaes_context->context = NULL;

	if( libcaes_context_initialize(
	     &( pycaes_context->context ),
	     &error ) != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize context.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a context object
 */
void pycaes_context_free(
      pycaes_context_t *pycaes_context )
{
	struct _typeobject *ob_type = NULL;
	libcerror_error_t *error    = NULL;
	static char *function       = "pycaes_context_free";
	int result                  = 0;

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid context.",
		 function );

		return;
	}
	if( pycaes_context->context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid context - missing libcaes context.",
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

	result = libcaes_context_free(
	          &( pycaes_context->context ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libcaes context.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pycaes_context );
}

/* Sets the key
 * Returns a Python object if successful or NULL on error
 */
PyObject *pycaes_context_set_key(
           pycaes_context_t *pycaes_context,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *string_object     = NULL;
	libcerror_error_t *error    = NULL;
	static char *function       = "pycaes_context_set_key";
	char *key_data              = NULL;
	static char *keyword_list[] = { "mode", "key", NULL };
        Py_ssize_t key_data_size    = 0;
	int mode                    = 0;
	int result                  = 0;

	if( pycaes_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid context.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "iO",
	     keyword_list,
	     &mode,
	     &string_object ) == 0 )
	{
		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	key_data = PyBytes_AsString(
	            string_object );

	key_data_size = PyBytes_Size(
	                 string_object );
#else
	key_data = PyString_AsString(
	            string_object );

	key_data_size = PyString_Size(
	                 string_object );
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
	Py_BEGIN_ALLOW_THREADS

	result = libcaes_context_set_key(
	          pycaes_context->context,
	          mode,
	          (uint8_t *) key_data,
	          (size_t) ( key_data_size * 8 ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pycaes_error_raise(
		 error,
		 PyExc_ValueError,
		 "%s: unable to set key.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

