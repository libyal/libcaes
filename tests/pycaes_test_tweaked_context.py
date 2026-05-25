#!/usr/bin/env python3
#
# Python-bindings tweaked_context type test script
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


class TweakedContextTypeTests(unittest.TestCase):
    """Tests the tweaked_context type."""

    _TEST_KEY = (
        b"\xc4\x3c\xd0\xb2\x37\x98\xee\x3d\xb0\x05\x3d\x1e\x4d\x18\x5e\x96\x5d\x67\xfd"
        b"\xda\x8c\x53\x25\xcc\x70\x9f\xc3\x97\x3f\x05\xcd\x17"
    )

    def test_set_keys(self):
        """Tests the set_keys function."""
        caes_tweaked_context = pycaes.tweaked_context()
        caes_tweaked_context.set_keys(
            pycaes.crypt_modes.ENCRYPT, self._TEST_KEY[:16], self._TEST_KEY[16:]
        )


class TweakedContextTypeConcurrencyTest(unittest.TestCase):
    """Tests the concurrency of the tweaked_context type."""

    _TEST_KEY = (
        b"\xc4\x3c\xd0\xb2\x37\x98\xee\x3d\xb0\x05\x3d\x1e\x4d\x18\x5e\x96\x5d\x67\xfd"
        b"\xda\x8c\x53\x25\xcc\x70\x9f\xc3\x97\x3f\x05\xcd\x17"
    )

    def test_concurrent_set_keys(self):
        """Tests the set_keys function from multiple threads concurrently."""
        caes_tweaked_context = pycaes.tweaked_context()

        def worker():
            """Thread worker function."""
            for _ in range(1000):
                caes_tweaked_context.set_keys(
                    pycaes.crypt_modes.ENCRYPT, self._TEST_KEY[:16], self._TEST_KEY[16:]
                )

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
