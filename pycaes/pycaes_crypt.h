/*
 * Python definition of the libcaes crypt functions
 *
 * Copyright (C) 2011-2015, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _PYCAES_CRYPT_H )
#define _PYCAES_CRYPT_H

#include <common.h>
#include <types.h>

#include "pycaes_libcaes.h"
#include "pycaes_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

PyObject *pycaes_crypt_cbc(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pycaes_crypt_ccm(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pycaes_crypt_ecb(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

PyObject *pycaes_crypt_xts(
           PyObject *self,
           PyObject *arguments,
           PyObject *keywords );

#if defined( __cplusplus )
}
#endif

#endif

