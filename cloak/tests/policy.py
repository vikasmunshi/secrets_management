#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.policy """
import unittest

import cloak


class UnitTestsPolicy(unittest.TestCase):
    from .test_data import valid_policy_dicts, invalid_policy_dicts

    def test_BasicConstraints(self):
        for basic_constraints_dict in (policy_dict.get('basic_constraints') for policy_dict in self.valid_policy_dicts):
            if basic_constraints_dict is not None:
                basic_constraints = cloak.BasicConstraints(**basic_constraints_dict)
                self.assertTrue(basic_constraints.ca is basic_constraints_dict.get('ca', False))
                self.assertTrue(basic_constraints.path_length is basic_constraints_dict.get('path_length'))

    def test_KeyUsage(self):
        for key_usage_dict in (policy_dict.get('key_usage') for policy_dict in self.valid_policy_dicts):
            if key_usage_dict is not None:
                key_usage = cloak.KeyUsage(**key_usage_dict)
                self.assertTrue(all(getattr(key_usage, usage) is key_usage_dict.get(usage, False)
                                    for usage in ('digital_signature', 'content_commitment', 'key_encipherment',
                                                  'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign',
                                                  'encipher_only', 'decipher_only',)))

    def test_Policy(self):
        for policy_dict in self.invalid_policy_dicts:
            with self.assertRaises(AssertionError):
                cloak.Policy.from_dict(policy_dict)

    def test_Policy_to_from_dict(self):
        for policy_dict in self.valid_policy_dicts:
            policy = cloak.Policy.from_dict(policy_dict)
            for key in ('subject', 'subject_alt_names', 'key_usage'):
                self.assertEqual(policy_dict[key], policy.to_dict()[key])
            basic_constraints = policy_dict.get('basic_constraints', {})
            self.assertEqual(basic_constraints.get('ca', False), policy.basic_constraints.ca)
            self.assertEqual(basic_constraints.get('path_length'), policy.basic_constraints.path_length)
        for policy_dict in self.invalid_policy_dicts:
            with self.assertRaises(AssertionError):
                cloak.Policy.from_dict(policy_dict)

    def test_policy_to_from_file(self):
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile() as temp_file:
            filename = temp_file.name
            for policy_dict in self.valid_policy_dicts:
                policy = cloak.Policy.from_dict(policy_dict)
                policy.to_file(filename=filename)
                self.assertEqual(policy, cloak.Policy.from_file(filename=filename))

    def test_SubjectAttributeOID(self):
        for attrib in cloak.subject_attribute_names:
            self.assertIsInstance(cloak.SubjectAttributeOID[attrib].value, cloak.policy.x509.oid.ObjectIdentifier)
            self.assertEqual(attrib, cloak.SubjectAttributeOID[attrib].value._name)

    def test_subject_attribute_names(self):
        self.assertEqual(
            sorted(cloak.subject_attribute_names),
            sorted(e.name for e in cloak.SubjectAttributeOID)
        )
