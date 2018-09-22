#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Run all unit tests for cloak """
import unittest

from .crypt import UnitTestsCrypt
from .csr import UnitTestsCSR
from .policy import UnitTestsPolicy
from .split import UnitTestsSplit

__all__ = (
    'run_tests',
)


def run_tests():
    suite = unittest.TestSuite()

    for test in (UnitTestsCrypt, UnitTestsCSR, UnitTestsPolicy, UnitTestsSplit):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test))

    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    run_tests()
