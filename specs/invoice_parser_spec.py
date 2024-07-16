# -*- coding: utf-8 -*-
from expects import *
from facturae.facturae_parser import FacturaeParser

with description('Facturae Invoice'):
    with before.each:
        with open('./specs/assets/facturae.xsig', 'rb') as f:
            xml_data = f.read()
            self.facturae = FacturaeParser(xml_data)

    with context('parse'):
        with it('worked as expected'):
            expect(self.facturae.sollicitud).to(equal('F19001666A29446424'))
            expect(self.facturae.vat_source).to(equal('A29446424'))
            expect(self.facturae.vat_destination).to(equal('B51065928'))
            expect(self.facturae.num_factures).to(equal('1'))
            expect(self.facturae.total_factures).to(equal('92.83'))
            expect(self.facturae.factures[0]['InvoiceNumber']).to(equal('F19001666'))

