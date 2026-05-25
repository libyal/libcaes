#!/usr/bin/env python3
#
# Python-bindings support functions test script
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

import sys
import unittest

import pycaes


def is_free_threaded_python():
    """True when running on a free-threaded Python build."""
    # pylint: disable=protected-access
    return hasattr(sys, "_is_gil_enabled") and not sys._is_gil_enabled()


class SupportFunctionsTests(unittest.TestCase):
    """Tests the support functions."""

    @unittest.skipUnless(
        is_free_threaded_python(), "requires a free-threaded Python build"
    )
    def test_gil_enforcement(self):
        """Test if the module enforces the GIL in a free-threaded Python."""
        # pylint: disable=protected-access
        self.assertFalse(sys._is_gil_enabled())

    def test_get_version(self):
        """Tests the get_version function."""
        version = pycaes.get_version()
        self.assertIsNotNone(version)


if __name__ == "__main__":
    unittest.main(verbosity=2)
