#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest

from .__init__ import __version__
from .core import UnitTestsCore
from .pki import UnitTestsPKI
from .secret_sharing import UnitTestsSecretSharing
from .version import UnitTestsVersion

print('Running Unit Tests Version {}'.format(__version__))

suite = unittest.TestSuite()

for test in (UnitTestsCore, UnitTestsSecretSharing, UnitTestsPKI, UnitTestsVersion):
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test))

unittest.TextTestRunner(verbosity=2).run(suite)
