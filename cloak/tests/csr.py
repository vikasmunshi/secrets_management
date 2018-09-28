#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.csr """
import unittest

import cloak


class UnitTestsCSR(unittest.TestCase):
    from .test_data import rsa_key, test_policies

    @staticmethod
    def change_policy(policy: cloak.Template) -> (cloak.Template, ...):
        return (
            cloak.Template(
                subject=(('commonName', 'wrong common name'),),
                subject_alt_names=policy.subject_alt_names,
                key_usage=policy.key_usage,
                basic_constraints=policy.basic_constraints
            ),
            cloak.Template(
                subject=policy.subject,
                subject_alt_names=('wrong.com',),
                key_usage=policy.key_usage,
                basic_constraints=policy.basic_constraints
            ),
            cloak.Template(
                subject=policy.subject,
                subject_alt_names=policy.subject_alt_names,
                key_usage=cloak.KeyUsage(digital_signature=not policy.key_usage.digital_signature),
                basic_constraints=policy.basic_constraints
            ),
            cloak.Template(
                subject=policy.subject,
                subject_alt_names=policy.subject_alt_names,
                key_usage=policy.key_usage,
                basic_constraints=cloak.BasicConstraints(ca=not policy.basic_constraints.ca, path_length=3)
            ),
        )

    def test_csr_main(self):
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile() as temp_file:
            filename = temp_file.name


    def test_check_csr(self):
        for policy in self.test_policies:
            csr = cloak.new_certificate_signing_request(template=policy, rsa_key=self.rsa_key)
            self.assertEqual('', cloak.check_csr(csr=csr, template=policy))
            for policy_err in self.change_policy(policy):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=policy_err))

    def test_check_csr_str(self):
        for policy in self.test_policies:
            _, csr_str = cloak.str_dump_new_certificate_signing_request_and_key(template=policy)
            self.assertEqual('', cloak.check_csr_str(csr=csr_str, template=policy))
            for policy_err in self.change_policy(policy):
                self.assertNotEqual('', cloak.check_csr_str(csr=csr_str, template=policy_err))

    def test_new_certificate_signing_request(self):
        for policy in self.test_policies:
            csr = cloak.new_certificate_signing_request(template=policy, rsa_key=self.rsa_key)
            self.assertIsInstance(csr, cloak.csr.x509.CertificateSigningRequest)
            self.assertTrue(csr.is_signature_valid)
            for policy_err in self.change_policy(policy):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=policy_err))

    def test_str_dump_new_certificate_signing_request_and_key(self):
        for policy in self.test_policies:
            key_str, csr_str = cloak.str_dump_new_certificate_signing_request_and_key(template=policy)

            self.assertIsInstance(key_str, str)
            self.assertIsInstance(cloak.rsa_key_from_str(key_str=key_str), cloak.csr.rsa.RSAPrivateKey)

            self.assertIsInstance(csr_str, str)
            self.assertEqual('', cloak.check_csr_str(csr=csr_str, template=policy))
            for policy_err in self.change_policy(policy):
                self.assertNotEqual('', cloak.check_csr_str(csr=csr_str, template=policy_err))

            csr = cloak.csr.x509.load_pem_x509_csr(data=csr_str.encode(), backend=cloak.csr.backend)
            self.assertIsInstance(csr, cloak.csr.x509.CertificateSigningRequest)
            self.assertTrue(csr.is_signature_valid)
            for policy_err in self.change_policy(policy):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=policy_err))
