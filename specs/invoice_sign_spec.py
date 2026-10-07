# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, '.')

from facturae import facturae
import signxml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import specs as test_data

import logging
#logging.basicConfig(level=logging.DEBUG)


def clean_cert_str(cert):
    """
    Clean'up an string representation of a certificate
    """
    return cert.replace("-----BEGIN CERTIFICATE-----","").\
                replace("-----END CERTIFICATE-----","").\
                replace("\n","")


with description('Invoice'):
    with before.each:
        self.invoice = facturae.FacturaeRoot()

        header = None
        parties = None
        invoices = None

        self.invoice.feed({
            'fileheader': header,
            'parties': parties,
            'invoices': invoices,
        })

        assert test_data.CERTIFICATE and test_data.CERTIFICATE_PASSWD and test_data.CERTIFICATE_PUBLIC
        self.certificate = open(test_data.CERTIFICATE, 'rb').read()
        self.certificate_public = clean_cert_str(open(test_data.CERTIFICATE_PUBLIC).read())
        self.password = test_data.CERTIFICATE_PASSWD

    with context('sign'):
        with it('must work as expected'):
            signed = self.invoice.sign(self.certificate, self.password)

            # [!] Public component of provided cert must be inside the signed XML
            assert self.certificate_public in signed, "Expected current certificate '{}' must be inside the signed Invoice".format(test_data.CERTIFICATE_PUBLIC)

            _key, certificate, _chain = pkcs12.load_key_and_certificates(
                self.certificate,
                self.password.encode('utf-8'),
            )
            verified = signxml.XMLVerifier().verify(
                signed,
                x509_cert=certificate.public_bytes(
                    serialization.Encoding.PEM
                ),
            )
            assert verified.signed_xml is not None

        with it('must report an invalid PKCS12 password'):
            try:
                self.invoice.sign(self.certificate, 'invalid-password')
            except ValueError:
                pass
            else:
                raise AssertionError("An invalid PKCS12 password must fail")
