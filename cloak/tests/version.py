#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.version """
import unittest

import cloak


class UnitTestsVersion(unittest.TestCase):
    def test_version(self):
        self.assertEqual(cloak.__version__, cloak.tests.__version__)
        print(cloak.__version__, end=' ... ', flush=True)
