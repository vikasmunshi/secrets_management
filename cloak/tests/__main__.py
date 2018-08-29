#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

from .pki import UnitTestsPKI
from .primitives import UnitTestsPrimitives
from .secret_sharing import UnitTestsSecretSharing

suite = unittest.TestSuite()

for test in (UnitTestsPrimitives, UnitTestsSecretSharing, UnitTestsPKI):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test))

unittest.TextTestRunner(verbosity=2).run(suite)
