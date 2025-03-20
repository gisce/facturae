# -*- coding: utf-8 -*-

from OpenSSL import crypto

class FacturaeUtils(object):

    @staticmethod
    def extract_from_pkcs12(pk, passwd):
        """
        Return the key and the cert from a PKCS12
        """

        assert pk, "PKCS12 must be provided"
        assert passwd, "Passwd must be provided"

        try:
            p12 = crypto.load_pkcs12(pk, passwd)

            priv_key = crypto.dump_privatekey(
                crypto.FILETYPE_PEM, p12.get_privatekey()
            )

            cert = crypto.dump_certificate(
                crypto.FILETYPE_PEM, p12.get_certificate()
            )

            return priv_key, cert

        except Exception as e:
            pass
