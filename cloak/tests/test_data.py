#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" test data """

csr_info_list = (
    {
        'subject': (('CN', 'name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit')),
        'extensions': (('keyUsage', False, 'Digital Signature, Key Encipherment'),),
        'subjectAltName': ''},
    {
        'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
        'extensions': (('keyUsage', True, 'Digital Signature'), ('basicConstraints', False, 'CA:TRUE')),
        'subjectAltName': 'www.test.org'},
    {
        'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
        'extensions': (('keyUsage', True, 'Key Encipherment'), ('basicConstraints', True, 'CA:TRUE')),
        'subjectAltName': 'www.test, test.org'}
)

invalid_csr_info_list = (
    {
        'subject': (
            ('CN', 'common name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit'),
            ('OU', 'org unit 2')),  # subject OID must be unique
        'extensions': (('keyUsage', False, 'Digital Signature, Key Encipherment'),
                       ('basicConstraints', False, 'CA:FALSE')),
        'subjectAltName': ''
    },
    {
        'subject': (('CN', 'xxx'), ('C', 'xx'), ('ST', 'xx'), ('L', 'x'), ('O', 'o'), ('OU', 'ou')),
        'extensions': (('keyusage', True, 'Digital Signature, Key Encipherment'),  # invalid extension
                       ('basicConstraints', True, 'CA:TRUE')),
        'subjectAltName': 'www.test, test.org'
    },
    {
        'subject': (('CN', 'common name'),
                    ('C', 'XXX'),  # invalid country code
                    ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit'), ('OU', 'org unit2')),
        'extensions': (('keyUsage', True, 'Digital Signature, Key Encipherment'),
                       ('basicConstraints', True, 'CA:TRUE')),
        'subjectAltName': 'www.test, test.org'
    },
    {
        'subject': (),  # empty subject
        'extensions': (('keyUsage', True, 'Digital Signature, Key Encipherment'),
                       ('basicConstraints', True, 'CA:TRUE')),
        'subjectAltName': 'www.test, test.org'
    }
)

sample_csr = (
    '\n'.join(l.strip() for l in """
        -----BEGIN CERTIFICATE REQUEST-----
        MIIC6jCCAdICAQMwYzEUMBIGA1UEAwwLY29tbW9uIG5hbWUxCzAJBgNVBAYTAnh4
        MQ4wDAYDVQQIDAVzdGF0ZTENMAsGA1UEBwwEY2l0eTEMMAoGA1UECgwDb3JnMREw
        DwYDVQQLDAhvcmcgdW5pdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
        AM86fLi2dz82Ge0ueM19JpybWD4AfwZYtSnQhm+JyOIU6DlqYb2R58oONsBhhiAm
        m2GYONIY0sYa7g9Yz6nXbGdHE0p+CTUZ84fwc2vydxB+wN/fdaD4dIx+pzQWsrLD
        Q/A2KCmBTk4/nSftDGWgWM1f/Q+oJbVcw4kuUyaIsvGB/902tiQQRdbs1mLkiCKp
        kLjR5oDpQciiDSnC52qdSk4w4u9zsSXNtthtVkNrmjbPELjLrr2zLyXHJhkdE9Ig
        x64PdocLjbQyjMXubiR2ZJts6m/ciMXu9NoQoKasyueazbNfLgaJlp56YlCW6Z1k
        9zhLm0UUzzOsrLhKyCH1PgECAwEAAaBCMEAGCSqGSIb3DQEJDjEzMDEwCwYDVR0P
        BAQDAgWgMAkGA1UdEwQCMAAwFwYDVR0RBBAwDoIMd3d3LnRlc3Qub3JnMA0GCSqG
        SIb3DQEBCwUAA4IBAQA/yIYuhAJe46xRL8QEcvQC4Y2KliM1TJPKjoN37Tsc/JUV
        ou3JVsqU2tHZRUY4CWHCB1adBddRgpIoZyOWCknrB8A73cmI3J8AlBEAGVWtBtrF
        YJfv9EKoLuq9Y9Z2RkwH18GsQ/DChJub0kcy3ldV+d9jLF+gijsuO/aYt0Rm5aXr
        5HnQH60S82875O+9cBxeSUK5P5uI8GEaj75i0W9Z1TKvakJXdgVP5vfHq/kw2Mjw
        Sp55ZsvFUNWHSyDc0U0WhVzUVm8BISY/bWIXGPKDmcvRR8rV90yoiAT3oPpuO6Lw
        aV3Datj0i8Z/KeVicmvAoyD1R2W5BcTFbs7u3gf8
        -----END CERTIFICATE REQUEST-----
        """.splitlines()),
    (
        (('CN', 'common name'), ('C', 'xx'), ('ST', 'state'), ('L', 'city'), ('O', 'org'), ('OU', 'org unit')),
        (('keyUsage', False, 'Digital Signature, Key Encipherment'), ('basicConstraints', False, 'CA:FALSE')),
        'www.test.org'
    )
)

sample_shares = (
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 15288, 39035651000266523388257098428752),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 102107, 85125624943142962423672069361793),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 277117, 115567609181130133573148417181602),
    ('6046ea4c-32a5-47a1-be00-be74110aa566', 107, 628607, 156452236128381489434170869187611)
)
