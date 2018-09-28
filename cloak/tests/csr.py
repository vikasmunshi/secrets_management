#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Unit tests for cloak.csr """
import unittest

import cloak


class UnitTestsCSR(unittest.TestCase):
    from .test_data import rsa_key, test_templates

    @staticmethod
    def change_template(template: cloak.Template) -> (cloak.Template, ...):
        return (
            cloak.Template(
                id=template.id,
                policy=template.policy,
                subject=(('commonName', 'wrong common name'),),
                subject_alt_names=template.subject_alt_names,
                key_usage=template.key_usage,
                basic_constraints=template.basic_constraints
            ),
            cloak.Template(
                id=template.id,
                policy=template.policy,
                subject=template.subject,
                subject_alt_names=('wrong.com',),
                key_usage=template.key_usage,
                basic_constraints=template.basic_constraints
            ),
            cloak.Template(
                id=template.id,
                policy=template.policy,
                subject=template.subject,
                subject_alt_names=template.subject_alt_names,
                key_usage=cloak.KeyUsage(digital_signature=not template.key_usage.digital_signature),
                basic_constraints=template.basic_constraints
            ),
            cloak.Template(
                id=template.id,
                policy=template.policy,
                subject=template.subject,
                subject_alt_names=template.subject_alt_names,
                key_usage=template.key_usage,
                basic_constraints=cloak.BasicConstraints(ca=not template.basic_constraints.ca, path_length=3)
            ),
        )

    # def test_csr_main(self):
    #     from tempfile import NamedTemporaryFile
    #     with NamedTemporaryFile() as temp_file:
    #         filename = temp_file.name

    def test_check_csr(self):
        for template in self.test_templates:
            csr = cloak.new_certificate_signing_request(template=template, rsa_key=self.rsa_key)
            self.assertEqual('', cloak.check_csr(csr=csr, template=template))
            for template_err in self.change_template(template):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=template_err))

    def test_check_csr_str(self):
        for template in self.test_templates:
            _, csr_str = cloak.str_dump_new_certificate_signing_request_and_key(template=template)
            self.assertEqual('', cloak.check_csr_str(csr=csr_str, template=template))
            for template_err in self.change_template(template):
                self.assertNotEqual('', cloak.check_csr_str(csr=csr_str, template=template_err))

    def test_new_certificate_signing_request(self):
        for template in self.test_templates:
            csr = cloak.new_certificate_signing_request(template=template, rsa_key=self.rsa_key)
            self.assertIsInstance(csr, cloak.csr.x509.CertificateSigningRequest)
            self.assertTrue(csr.is_signature_valid)
            for template_err in self.change_template(template):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=template_err))

    def test_str_dump_new_certificate_signing_request_and_key(self):
        for template in self.test_templates:
            key_str, csr_str = cloak.str_dump_new_certificate_signing_request_and_key(template=template)

            self.assertIsInstance(key_str, str)
            self.assertIsInstance(cloak.rsa_key_from_str(key_str=key_str), cloak.csr.rsa.RSAPrivateKey)

            self.assertIsInstance(csr_str, str)
            self.assertEqual('', cloak.check_csr_str(csr=csr_str, template=template))
            for template_err in self.change_template(template):
                self.assertNotEqual('', cloak.check_csr_str(csr=csr_str, template=template_err))

            csr = cloak.csr.x509.load_pem_x509_csr(data=csr_str.encode(), backend=cloak.csr.backend)
            self.assertIsInstance(csr, cloak.csr.x509.CertificateSigningRequest)
            self.assertTrue(csr.is_signature_valid)
            for template_err in self.change_template(template):
                self.assertNotEqual('', cloak.check_csr(csr=csr, template=template_err))
