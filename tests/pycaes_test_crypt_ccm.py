#!/usr/bin/env python
#
# Python-bindings AES-CCM de/encryption testing program
#
# Copyright (C) 2011-2024, Joachim Metz <joachim.metz@gmail.com>
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
#

import sys

import pycaes


def pycaes_test_crypt_ccm(mode, key, nonce, input_data, expected_output_data):
  caes_context = pycaes.context()
  # The key must be set in encryption mode (LIBCAES_CRYPT_MODE_ENCRYPT)
  # for both de- and encryption.
  caes_context.set_key(pycaes.crypt_modes.ENCRYPT, key)

  output_data = pycaes.crypt_ccm(caes_context, mode, nonce, input_data)

  return output_data == expected_output_data


def main():
  key = [
      0x8a, 0x29, 0x41, 0xff, 0x7b, 0x3a, 0x5e, 0xe9, 0x0b, 0xca, 0x70, 0xfb, 
      0xb2, 0x65, 0xaf, 0xab, 0xed, 0x68, 0xb1, 0x55, 0x07, 0x65, 0x25, 0x55,
      0x40, 0xc8, 0x86, 0x1e, 0x13, 0x7e, 0xd0, 0x94 ]

  nonce = [
      0x60, 0xd5, 0x17, 0x86, 0x5b, 0x53, 0xcc, 0x01, 0x03, 0x00, 0x00, 0x00 ]

  cipher_text = [
      0xa8, 0xdf, 0x3d, 0x7c, 0x99, 0x74, 0x2c, 0x49, 0x68, 0x85, 0x70, 0x84, 
      0x6a, 0xd5, 0xf8, 0x0c, 0x6b, 0x66, 0xc6, 0x8a, 0x3e, 0x30, 0xb7, 0x5b,
      0xed, 0x61, 0x52, 0x9c, 0x73, 0xce, 0x36, 0x5c, 0xa1, 0x96, 0x0e, 0x91,
      0xa1, 0x48, 0x83, 0x67, 0x8d, 0x09, 0x41, 0xde, 0x51, 0x0b, 0x04, 0x49,
      0xa4, 0x19, 0xb5, 0x1e, 0x49, 0xd2, 0xac, 0xfd, 0x6a, 0x0a, 0x78, 0x8c ]

  plain_text = [
      0x18, 0x27, 0x1c, 0x74, 0xeb, 0x49, 0x16, 0xbf, 0x6b, 0x46, 0x31, 0x74, 
      0x15, 0x41, 0xf1, 0x99, 0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x03, 0x20, 0x00, 0x00, 0x68, 0x8a, 0x51, 0x70, 0x06, 0x14, 0xdb, 0xd1,
      0xc1, 0x00, 0xf5, 0x68, 0xc4, 0xbd, 0x29, 0xa6, 0x3c, 0x46, 0x36, 0x72,
      0xbe, 0x6b, 0xde, 0xf5, 0x4b, 0x91, 0x8b, 0xb9, 0xa3, 0xa4, 0x3c, 0xbc ]

  print("Testing AES-CCM 256-bit decryption\t"),

  test_key = bytes(bytearray(key))
  test_nonce = bytes(bytearray(nonce))
  test_cipher_text = bytes(bytearray(cipher_text))
  test_plain_text = bytes(bytearray(plain_text))

  result = pycaes_test_crypt_ccm(
      pycaes.crypt_modes.DECRYPT, test_key, test_nonce, test_cipher_text,
      test_plain_text)

  if not result:
    print("(FAIL)")
  else:
    print("(PASS)")

  if not result:
    return False

  print("Testing AES-CCM 256-bit encryption\t"),

  test_key = bytes(bytearray(key))
  test_nonce = bytes(bytearray(nonce))
  test_cipher_text = bytes(bytearray(cipher_text))
  test_plain_text = bytes(bytearray(plain_text))

  result = pycaes_test_crypt_ccm(
      pycaes.crypt_modes.ENCRYPT, test_key, test_nonce, test_plain_text,
      test_cipher_text)

  if not result:
    print("(FAIL)")
  else:
    print("(PASS)")

  if not result:
    return False

  return True


if __name__ == "__main__":
  if not main():
    sys.exit(1)
  else:
    sys.exit(0)

