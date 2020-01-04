/*
 * Python object definition of the libcaes crypt modes
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

#if !defined( _PYCAES_CRYPT_MODES_H )
#define _PYCAES_CRYPT_MODES_H

#include <common.h>
#include <types.h>

#include "pycaes_libcaes.h"
#include "pycaes_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pycaes_crypt_modes pycaes_crypt_modes_t;

struct pycaes_crypt_modes
{
	/* Python object initialization
	 */
	PyObject_HEAD
};

extern PyTypeObject pycaes_crypt_modes_type_object;

int pycaes_crypt_modes_init_type(
     PyTypeObject *type_object );

PyObject *pycaes_crypt_modes_new(
           void );

int pycaes_crypt_modes_init(
     pycaes_crypt_modes_t *definitions_object );

void pycaes_crypt_modes_free(
      pycaes_crypt_modes_t *definitions_object );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYCAES_CRYPT_MODES_H ) */

