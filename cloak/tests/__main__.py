#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

from .core import UnitTestsCore
from .pki import UnitTestsPKI
from .secret_sharing import UnitTestsSecretSharing

suite = unittest.TestSuite()

for test in (UnitTestsCore, UnitTestsSecretSharing, UnitTestsPKI):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test))

unittest.TextTestRunner(verbosity=2).run(suite)
