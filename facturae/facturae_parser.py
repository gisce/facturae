# -*- coding: utf-8 -*-
from functools import reduce
from lxml import objectify


class FacturaeParser(object):

    def __init__(self, xml_data):
        """Construir Facturae Parser"""
        self.xml_data = xml_data
        try:
            self.xml_obj = objectify.fromstring(self.xml_data)
            self.xml_dict = self.parse_xml()
            self.sollicitud = self.xml_dict.get('BatchIdentifier', False)
            self.num_factures = self.xml_dict.get('InvoicesCount', False)
            self.total_factures = self.xml_dict.get('TotalInvoicesAmount', False)
            self.total_executable = self.xml_dict.get('TotalExecutableAmount', False)
            self.seller = self.xml_dict.get('seller', False)
            self.buyer = self.xml_dict.get('buyer', False)
            self.issuer_type = self.xml_dict.get('InvoiceIssuerType')
            self.vat_source = self._get_from_dict(self.xml_dict, ['seller', 'TaxIdentificationNumber'])
            self.vat_destination = self._get_from_dict(self.xml_dict, ['buyer', 'TaxIdentificationNumber'])
            self.factures = [invoice for invoice in self.xml_dict.get('Invoices')]
        except:
            print('Something went really wrong.')

    def parse_xml(self):
        res = {}

        res.update(self.get_header_dict(self.xml_obj))
        res.update(self.get_parties_dict(self.xml_obj))
        res.update(self.get_invoices_dict(self.xml_obj))

        return res

    def get_header_dict(self, xml_obj):
        res = {}

        header = xml_obj.find('FileHeader')
        batch = header.find('Batch')

        if header is not None:
            res.update({
                'SchemaVersion': header.SchemaVersion.text if header.find(
                    'SchemaVersion') is not None else False,
                'Modality': header.Modality.text if header.find(
                    'Modality') is not None else False,
                'InvoiceIssuerType': header.InvoiceIssuerType.text if header.find(
                    'InvoiceIssuerType') is not None else False,
            })

        if batch is not None:
            res.update({
                'BatchIdentifier': batch.BatchIdentifier.text if batch.find(
                    'BatchIdentifier') is not None else False,
                'InvoicesCount': batch.InvoicesCount.text if batch.find(
                    'InvoicesCount') is not None else False,
                'TotalInvoicesAmount': batch.TotalInvoicesAmount.TotalAmount.text if batch.find(
                    'TotalInvoicesAmount') is not None else False,
                'TotalOutstandingAmount': batch.TotalOutstandingAmount.TotalAmount.text if batch.find(
                    'TotalOutstandingAmount') is not None else False,
                'TotalExecutableAmount': batch.TotalExecutableAmount.TotalAmount.text if batch.find(
                    'TotalExecutableAmount') is not None else False,
                'InvoiceCurrencyCode': batch.InvoiceCurrencyCode.text if batch.find(
                    'InvoiceCurrencyCode') is not None else False,
            })

        return res

    def get_parties_dict(self, xml_obj):
        res = {'seller': {}, 'buyer': {}}
        parties = xml_obj.find('Parties')

        if parties is not None:
            seller = parties.SellerParty
            buyer = parties.BuyerParty

            if seller is not None:
                res['seller'] = self._get_party_data(seller)

            if buyer is not None:
                res['buyer'] = self._get_party_data(buyer)

        return res

    def _get_party_data(self, party):
        res = {}

        tax_identification = party.find('TaxIdentification')
        legal_entity = party.find('LegalEntity')

        if tax_identification is not None:
            res.update({
                'PersonTypeCode': tax_identification.PersonTypeCode.text if tax_identification.find(
                    'PersonTypeCode') is not None else False,
                'ResidenceTypeCode': tax_identification.ResidenceTypeCode.text if tax_identification.find(
                    'ResidenceTypeCode') is not None else False,
                'TaxIdentificationNumber': tax_identification.TaxIdentificationNumber.text if tax_identification.find(
                    'TaxIdentificationNumber') is not None else False,
            })

        if legal_entity is not None:
            res.update({
                'CorporateName': legal_entity.CorporateName.text if legal_entity.find(
                    'CorporateName') is not None else False,
                'TradeName': legal_entity.TradeName.text if legal_entity.find(
                    'TradeName') is not None else False,
            })

            party_address = legal_entity.find('AddressInSpain')

            if party_address is not None:
                res.update({
                    'Address': {
                        'Street': party_address.Address.text if party_address.find(
                            'Address') is not None else False,
                        'PostCode': party_address.PostCode.text if party_address.find(
                            'PostCode') is not None else False,
                        'Town': party_address.Town.text if party_address.find(
                            'Town') is not None else False,
                        'Province': party_address.Province.text if party_address.find(
                            'Province') is not None else False,
                        'CountryCode': party_address.CountryCode.text if party_address.find(
                            'CountryCode') is not None else False,
                    }
                })

        return res

    def get_invoices_dict(self, xml_obj):
        res = {'Invoices': []}
        invoices = xml_obj.find('Invoices')

        for invoice in invoices.findall('Invoice'):
            invoice_res = {}

            invoice_header = invoice.find('InvoiceHeader')
            if invoice_header is not None:
                invoice_res.update({
                    'InvoiceNumber': invoice_header.InvoiceNumber.text if invoice_header.find(
                        'InvoiceNumber') is not None else False,
                    'InvoiceSeriesCode': invoice_header.InvoiceSeriesCode.text if invoice_header.find(
                        'InvoiceSeriesCode') is not None else False,
                    'InvoiceDocumentType': invoice_header.InvoiceDocumentType.text if invoice_header.find(
                        'InvoiceDocumentType') is not None else False,
                    'InvoiceClass': invoice_header.InvoiceClass.text if invoice_header.find(
                        'InvoiceClass') is not None else False,
                })

            invoice_issue_data = invoice.find('InvoiceIssueData')
            if invoice_issue_data is not None:
                invoice_res.update({
                    'IssueDate': invoice_issue_data.IssueDate.text if invoice_issue_data.find(
                        'IssueDate') is not None else False,
                    'InvoiceCurrencyCode': invoice_issue_data.InvoiceCurrencyCode.text if invoice_issue_data.find(
                        'InvoiceCurrencyCode') is not None else False,
                    'TaxCurrencyCode': invoice_issue_data.TaxCurrencyCode.text if invoice_issue_data.find(
                        'TaxCurrencyCode') is not None else False,
                    'LanguageName': invoice_issue_data.LanguageName.text if invoice_issue_data.find(
                        'LanguageName') is not None else False,
                })

            invoice_res.update({
                'Taxes': self._get_taxes(invoice.TaxesOutputs) if invoice.find('TaxesOutputs') is not None else False,
            })

            invoice_totals = invoice.find('InvoiceTotals')
            if invoice_totals is not None:
                invoice_res.update({
                    'TotalGrossAmount': invoice_totals.TotalGrossAmount.text if invoice_totals.find(
                        'TotalGrossAmount') is not None else False,
                    'TotalGrossBeforeTaxes': invoice_totals.TotalGrossAmountBeforeTaxes.text if invoice_totals.find(
                        'TotalGrossAmountBeforeTaxes') is not None else False,
                    'TotalTaxOutputs': invoice_totals.TotalTaxOutputs.text if invoice_totals.find(
                        'TotalTaxOutputs') is not None else False,
                    'TotalTaxesWithheld': invoice_totals.TotalTaxesWithheld.text if invoice_totals.find(
                        'TotalTaxesWithheld') is not None else None,
                    'InvoiceTotal': invoice_totals.InvoiceTotal.text if invoice_totals.find(
                        'InvoiceTotal') is not None else False,
                    'TotalOutstandingAmount': invoice_totals.TotalOutstandingAmount.text if invoice_totals.find(
                        'TotalOutstandingAmount') is not None else False,
                    'AmountsWithheld': self._get_amounts_with_held(invoice_totals.AmountsWithheld) if invoice_totals.find(
                        'AmountsWithheld') is not None else None,
                    'TotalExecutableAmount': invoice_totals.TotalExecutableAmount.text if invoice_totals.find(
                        'TotalExecutableAmount') is not None else False,
                })

            invoice_res.update({
                'InvoiceLines': self._get_invoice_lines(invoice.Items) if invoice.find(
                    'Items') is not None else False,
            })

            payment_details = invoice.find('PaymentDetails')
            if payment_details is not None:
                installment = payment_details.find('Installment')
                if installment is not None:
                    invoice_res.update({
                        'InstallmentDueDate': installment.InstallmentDueDate.text if installment.find(
                            'InstallmentDueDate') is not None else False,
                        'InstallmentAmount': installment.InstallmentAmount.text if installment.find(
                            'InstallmentAmount') is not None else False,
                        'PaymentMeans': installment.PaymentMeans.text if installment.find(
                            'PaymentMeans') is not None else False,
                    })

                    bank_account = installment.find('AccountToBeDebited')
                    if bank_account is not None:
                        invoice_res.update({
                            'IBAN': bank_account.IBAN.text if bank_account.find(
                                'IBAN') is not None else False,
                            'BIC': bank_account.BIC.text if bank_account.find(
                                'BIC') is not None else False,
                        })

            additional_data = invoice.find('AdditionalData')
            if additional_data is not None:
                invoice_res.update({
                    'Attachments': self._get_attachments(additional_data.RelatedDocuments) if additional_data.find(
                        'RelatedDocuments') is not None else False,
                    'AdditionalInformation': additional_data.InvoiceAdditionalInformation.text if additional_data.find(
                        'InvoiceAdditionalInformation') is not None else False,
                })

            res['Invoices'].append(invoice_res)

        return res

    def _get_amounts_with_held(self, amountwhitheld):

        amounts_with_held = {
            'WithholdingReason': amountwhitheld.WithholdingReason.text if amountwhitheld.find(
                'WithholdingReason') is not None else None,
            'WithholdingRate': amountwhitheld.WithholdingRate.text if amountwhitheld.find(
                'WithholdingRate') is not None else None,
            'WithholdingAmount': amountwhitheld.WithholdingAmount.text if amountwhitheld.find(
                'WithholdingAmount') is not None else None
        }

        return amounts_with_held

    def _get_taxes(self, taxes):
        res = []

        for tax in taxes.findall('Tax'):
            tax_res = {
                'TaxTypeCode': tax.TaxTypeCode.text if tax.find(
                    'TaxTypeCode') is not None else False,
                'TaxRate': tax.TaxRate.text if tax.find(
                    'TaxRate') is not None else False,
                'TaxableBase': tax.TaxableBase.TotalAmount.text if tax.find(
                    'TaxableBase') is not None else False,
                'TaxAmount': tax.TaxAmount.TotalAmount.text if tax.find(
                    'TaxAmount') is not None else False,
            }
            res.append(tax_res)

        return res

    def _get_invoice_lines(self, items):
        res = []

        for line in items.findall('InvoiceLine'):
            line_res = {
                'ItemDescription': line.ItemDescription.text if line.find(
                    'ItemDescription') is not None else False,
                'Quantity': line.Quantity.text if line.find(
                    'Quantity') is not None else False,
                'UnitPriceWithoutTax': line.UnitPriceWithoutTax.text if line.find(
                    'UnitPriceWithoutTax') is not None else False,
                'TotalCost': line.TotalCost.text if line.find(
                    'TotalCost') is not None else False,
                'GrossAmount': line.GrossAmount.text if line.find(
                    'GrossAmount') is not None else False,
                'TaxesOutputs': self._get_taxes(line.TaxesOutputs) if line.find(
                    'TaxesOutputs') is not None else False,
            }
            res.append(line_res)

        return res

    def _get_attachments(self, related_documents):
        res = []

        for attachment in related_documents.findall('Attachment'):
            attachment_res = {
                'AttachmentCompressionAlgorithm': attachment.AttachmentCompressionAlgorithm.text if attachment.find(
                    'AttachmentCompressionAlgorithm') is not None else False,
                'AttachmentFormat': attachment.AttachmentFormat.text if attachment.find(
                    'AttachmentFormat') is not None else False,
                'AttachmentEncoding': attachment.AttachmentEncoding.text if attachment.find(
                    'AttachmentEncoding') is not None else False,
                'AttachmentData': attachment.AttachmentData.text if attachment.find(
                    'AttachmentData') is not None else False,
            }
            res.append(attachment_res)

        return res

    def _get_from_dict(self,dataDict, mapList):
        """Iterate nested dictionary"""
        return reduce(dict.get, mapList, dataDict)

