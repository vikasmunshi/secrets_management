#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Run all unit tests for cloak """
import unittest

from .crypt import UnitTestsCrypt
from .csr import UnitTestsCSR
from .template import UnitTestsTemplate
from .secret_sharing import UnitTestsSplit
from .version import UnitTestsVersion

__all__ = (
    'run_tests',
)


def run_tests():
    suite = unittest.TestSuite()

    for test in (UnitTestsCrypt, UnitTestsCSR, UnitTestsTemplate, UnitTestsSplit, UnitTestsVersion):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test))

    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    run_tests()
