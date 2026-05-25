#!/usr/bin/env python3
#
# Python-bindings AES-CCM de/encryption testing program
#
# Copyright (C) 2011-2026, Joachim Metz <joachim.metz@gmail.com>
#
# Refer to AUTHORS for acknowledgements.
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import os
import sys
import unittest

import pycaes


class CryptCcmTest(unittest.TestCase):
    """Tests the crypt_ccm function."""

    _TEST_VECTORS_256BIT = [
        {
            "key": "8a2941ff7b3a5ee90bca70fbb265afabed68b1550765255540c8861e137ed094",
            "nonce": "60d517865b53cc0103000000",
            "cipher_text": (
                "a8df3d7c99742c49688570846ad5f80c6b66c68a3e30b75bed61529c73ce365ca19"
                "60e91a14883678d0941de510b0449a419b51e49d2acfd6a0a788c"
            ),
            "plain_text": (
                "18271c74eb4916bf6b4631741541f1992c0000000100000003200000688a5170061"
                "4dbd1c100f568c4bd29a63c463672be6bdef54b918bb9a3a43cbc"
            ),
        },
    ]

    def _test_pycaes_crypt_ccm(
        self, index, mode, key, nonce, input_data, expected_output_data
    ):
        """Test decrypting or encrypting data with pycaes.crypt_ccm."""
        caes_context = pycaes.context()

        # Note that the key must be set in encryption mode (LIBCAES_CRYPT_MODE_ENCRYPT)
        # for both decryption and encryption.
        caes_context.set_key(pycaes.crypt_modes.ENCRYPT, key)

        output_data = pycaes.crypt_ccm(caes_context, mode, nonce, input_data)

        if mode == pycaes.crypt_modes.DECRYPT:
            message = f"Failed to decrypt test vector: {index:d}"
        else:
            message = f"Failed to encrypt test vector: {index:d}"

        self.assertEqual(output_data, expected_output_data, msg=message)

    def test_aes_ccm_256bit_decryption(self):
        """Tests AES-CCM 256-bit decryption."""
        for index, test_vector in enumerate(self._TEST_VECTORS_256BIT):
            key = bytes(bytearray.fromhex(test_vector["key"]))
            nonce = bytes(bytearray.fromhex(test_vector["nonce"]))
            cipher_text = bytes(bytearray.fromhex(test_vector["cipher_text"]))
            plain_text = bytes(bytearray.fromhex(test_vector["plain_text"]))

            self._test_pycaes_crypt_ccm(
                index,
                pycaes.crypt_modes.DECRYPT,
                key,
                nonce,
                cipher_text,
                plain_text,
            )

    def test_aes_ccm_256bit_encryption(self):
        """Tests AES-CCM 256-bit encryption."""
        for index, test_vector in enumerate(self._TEST_VECTORS_256BIT):
            key = bytes(bytearray.fromhex(test_vector["key"]))
            nonce = bytes(bytearray.fromhex(test_vector["nonce"]))
            cipher_text = bytes(bytearray.fromhex(test_vector["cipher_text"]))
            plain_text = bytes(bytearray.fromhex(test_vector["plain_text"]))

            self._test_pycaes_crypt_ccm(
                index,
                pycaes.crypt_modes.ENCRYPT,
                key,
                nonce,
                plain_text,
                cipher_text,
            )


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()

    options, unknown_options = argument_parser.parse_known_args()
    unknown_options.insert(0, sys.argv[0])

    unittest.main(argv=unknown_options, verbosity=2)
