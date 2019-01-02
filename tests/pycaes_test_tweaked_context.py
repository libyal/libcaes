#!/usr/bin/env python
#
# Python-bindings tweaked_context type test script
#
# Copyright (C) 2011-2019, Joachim Metz <joachim.metz@gmail.com>
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


class TweakedContextTypeTests(unittest.TestCase):
  """Tests the tweaked_context type."""


if __name__ == "__main__":
  argument_parser = argparse.ArgumentParser()


  options, unknown_options = argument_parser.parse_known_args()
  unknown_options.insert(0, sys.argv[0])



  unittest.main(argv=unknown_options, verbosity=2)
