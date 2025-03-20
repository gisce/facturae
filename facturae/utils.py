# -*- coding: utf-8 -*-

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
            priv_key, cert, other_certs = pkcs12.load_key_and_certificates(
                pk, passwd)

            return priv_key, cert

        except Exception as e:
            pass
