#!/usr/bin/env python3
#
# Python-bindings context type test script
#
# Copyright (C) 2011-2026, Joachim Metz <joachim.metz@gmail.com>
#
# Refer to AUTHORS for acknowledgements.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import os
import sys
import threading
import unittest

import pycaes


class ContextTypeTests(unittest.TestCase):
    """Tests the context type."""

    _TEST_KEY = (
        b"\x8a\x29\x41\xff\x7b\x3a\x5e\xe9\x0b\xca\x70\xfb\xb2\x65\xaf\xab\xed\x68\xb1"
        b"\x55\x07\x65\x25\x55\x40\xc8\x86\x1e\x13\x7e\xd0\x94"
    )

    def test_set_key(self):
        """Tests the set_key function."""
        caes_context = pycaes.context()
        caes_context.set_key(pycaes.crypt_modes.ENCRYPT, self._TEST_KEY)


class ContextTypeConcurrencyTest(unittest.TestCase):
    """Tests the concurrency of the context type."""

    _TEST_KEY = (
        b"\x8a\x29\x41\xff\x7b\x3a\x5e\xe9\x0b\xca\x70\xfb\xb2\x65\xaf\xab\xed\x68\xb1"
        b"\x55\x07\x65\x25\x55\x40\xc8\x86\x1e\x13\x7e\xd0\x94"
    )

    def test_concurrent_set_key(self):
        """Tests the set_key function from multiple threads concurrently."""
        caes_context = pycaes.context()

        def worker():
            """Thread worker function."""
            for _ in range(1000):
                caes_context.set_key(pycaes.crypt_modes.ENCRYPT, self._TEST_KEY)

        threads = [threading.Thread(target=worker) for _ in range(10)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()

    options, unknown_options = argument_parser.parse_known_args()
    unknown_options.insert(0, sys.argv[0])

    unittest.main(argv=unknown_options, verbosity=2)
