# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

class FacturaeUtils(object):

    @staticmethod
    def extract_from_pkcs12(pk, passwd):
        """
        Return the key and the cert from a PKCS12
        """

        assert pk, "PKCS12 must be provided"
        assert passwd, "Passwd must be provided"

        try:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pk, passwd)

            priv_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            cert = certificate.public_bytes(
                serialization.Encoding.PEM
            )

            return priv_key, cert

        except Exception as e:
            pass
