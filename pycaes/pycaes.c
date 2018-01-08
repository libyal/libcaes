/*
 * Python bindings module for libcaes (pycaes)
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
#include <narrow_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pycaes.h"
#include "pycaes_context.h"
#include "pycaes_crypt.h"
#include "pycaes_crypt_modes.h"
#include "pycaes_libcaes.h"
#include "pycaes_libcerror.h"
#include "pycaes_python.h"
#include "pycaes_tweaked_context.h"
#include "pycaes_unused.h"

/* The pycaes module methods
 */
PyMethodDef pycaes_module_methods[] = {
	{ "get_version",
	  (PyCFunction) pycaes_get_version,
	  METH_NOARGS,
	  "get_version() -> String\n"
	  "\n"
	  "Retrieves the version." },

	{ "crypt_cbc",
	  (PyCFunction) pycaes_crypt_cbc,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_cbc(context, mode, initialization_vector, data) -> String\n"
	  "\n"
	  "De- or encrypts a block of data using AES-CBC (Cipher Block Chaining)." },

	{ "crypt_ccm",
	  (PyCFunction) pycaes_crypt_ccm,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_ccm(context, mode, nonce, data) -> String\n"
	  "\n"
	  "De- or encrypts a block of data using AES-CCM (Counter with CBC-MAC)." },

#ifdef TODO
	{ "crypt_cfb",
	  (PyCFunction) pycaes_crypt_cfb,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_cfb(context, mode, initialization_vector, data) -> String\n"
	  "\n"
	  "De- or encrypts a block of data using AES-CFB (Cipher Feedback Mode)." },
#endif

	{ "crypt_ecb",
	  (PyCFunction) pycaes_crypt_ecb,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_ecb(context, mode, data) -> String\n"
	  "\n"
	  "De- or encrypts a block of data using AES-ECB (Electronic CodeBook)." },

	{ "crypt_xts",
	  (PyCFunction) pycaes_crypt_xts,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_xts(tweaked_context, mode, tweak_value, data) -> String\n"
	  "\n"
	  "De- or encrypts a block of data using AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing)." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

/* Retrieves the pycaes/libcaes version
 * Returns a Python object if successful or NULL on error
 */
PyObject *pycaes_get_version(
           PyObject *self PYCAES_ATTRIBUTE_UNUSED,
           PyObject *arguments PYCAES_ATTRIBUTE_UNUSED )
{
	const char *errors           = NULL;
	const char *version_string   = NULL;
	size_t version_string_length = 0;

	PYCAES_UNREFERENCED_PARAMETER( self )
	PYCAES_UNREFERENCED_PARAMETER( arguments )

	Py_BEGIN_ALLOW_THREADS

	version_string = libcaes_get_version();

	Py_END_ALLOW_THREADS

	version_string_length = narrow_string_length(
	                         version_string );

	/* Pass the string length to PyUnicode_DecodeUTF8
	 * otherwise it makes the end of string character is part
	 * of the string
	 */
	return( PyUnicode_DecodeUTF8(
	         version_string,
	         (Py_ssize_t) version_string_length,
	         errors ) );
}

#if PY_MAJOR_VERSION >= 3

/* The pycaes module definition
 */
PyModuleDef pycaes_module_definition = {
	PyModuleDef_HEAD_INIT,

	/* m_name */
	"pycaes",
	/* m_doc */
	"Python libcaes module (pycaes).",
	/* m_size */
	-1,
	/* m_methods */
	pycaes_module_methods,
	/* m_reload */
	NULL,
	/* m_traverse */
	NULL,
	/* m_clear */
	NULL,
	/* m_free */
	NULL,
};

#endif /* PY_MAJOR_VERSION >= 3 */

/* Initializes the pycaes module
 */
#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pycaes(
                void )
#else
PyMODINIT_FUNC initpycaes(
                void )
#endif
{
	PyObject *module                          = NULL;
	PyTypeObject *context_type_object         = NULL;
	PyTypeObject *crypt_modes_type_object     = NULL;
	PyTypeObject *tweaked_context_type_object = NULL;
	PyGILState_STATE gil_state                = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	libcaes_notify_set_stream(
	 stderr,
	 NULL );
	libcaes_notify_set_verbose(
	 1 );
#endif

	/* Create the module
	 * This function must be called before grabbing the GIL
	 * otherwise the module will segfault on a version mismatch
	 */
#if PY_MAJOR_VERSION >= 3
	module = PyModule_Create(
	          &pycaes_module_definition );
#else
	module = Py_InitModule3(
	          "pycaes",
	          pycaes_module_methods,
	          "Python libcaes module (pycaes)." );
#endif
	if( module == NULL )
	{
#if PY_MAJOR_VERSION >= 3
		return( NULL );
#else
		return;
#endif
	}
	PyEval_InitThreads();

	gil_state = PyGILState_Ensure();

	/* Setup the context type object
	 */
	pycaes_context_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pycaes_context_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pycaes_context_type_object );

	context_type_object = &pycaes_context_type_object;

	PyModule_AddObject(
	 module,
	 "context",
	 (PyObject *) context_type_object );

	/* Setup the tweaked context type object
	 */
	pycaes_tweaked_context_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pycaes_tweaked_context_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pycaes_tweaked_context_type_object );

	tweaked_context_type_object = &pycaes_tweaked_context_type_object;

	PyModule_AddObject(
	 module,
	 "tweaked_context",
	 (PyObject *) tweaked_context_type_object );

	/* Setup the crypt modes type object
	 */
	pycaes_crypt_modes_type_object.tp_new = PyType_GenericNew;

	if( pycaes_crypt_modes_init_type(
	     &pycaes_crypt_modes_type_object ) != 1 )
	{
		goto on_error;
	}
	if( PyType_Ready(
	     &pycaes_crypt_modes_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pycaes_crypt_modes_type_object );

	crypt_modes_type_object = &pycaes_crypt_modes_type_object;

	PyModule_AddObject(
	 module,
	 "crypt_modes",
	 (PyObject *) crypt_modes_type_object );

	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( module );
#else
	return;
#endif

on_error:
	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( NULL );
#else
	return;
#endif
}

