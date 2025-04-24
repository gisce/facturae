# -*- coding: utf-8 -*-

from libcomxml.core import XmlModel, XmlField
from .utils import FacturaeUtils
from signxml import XMLSigner, XMLVerifier
from xml.etree import ElementTree
from . import extensions

class FacturaeRoot(XmlModel):
    _sort_order = ('root', 'fileheader', 'parties', 'invoices', 'extensions')

    def __init__(self, utilities=False):

        nsmap = {'ds': 'http://www.w3.org/2000/09/xmldsig#',
                 'fe': 'http://www.facturae.gob.es/formato/Versiones/Facturaev3_2_2.xml'}

        if utilities:
            nsmap['utilities'] = 'http://www.facturae.es/Facturae/Extensions/Utilities'

        self.root = XmlField('Facturae', namespace=nsmap['fe'],
                             attributes={'nsmap': nsmap})
        self.fileheader = FileHeader()
        self.parties = Parties()
        self.invoices = Invoices()
        self.extensions = extensions.Extensions()
        super(FacturaeRoot, self).__init__('Facturae', 'root')

    def sign(self, certificate, password):
        """
        Sign an InvoiceRoot using the provided PKCS12 certificate

        :param certificate: must be the pkcs12 certificate
        :param password: must be the password of the certificate
        """

        xml = str(self)

        pkcs12_key, pkcs12_cert = FacturaeUtils.extract_from_pkcs12(
                                                pk=certificate, passwd=password)

        root = ElementTree.fromstring(xml)
        signed_root = XMLSigner().sign(root, key=pkcs12_key, cert=pkcs12_cert)

        string_signed_root = ElementTree.tostring(signed_root, encoding='utf8',
                                                  method='xml').replace("\n","")


        return string_signed_root

    def sign_verify(self, signed_root):
        """
        Verify the provided signature
        """
        return XMLVerifier().verify(data=signed_root,
                                            require_x509=False).signed_xml


# 1


class FileHeader(XmlModel):

    _sort_order = ('root', 'schemaversion', 'modality',
                   'invoiceissuertype', 'batch')

    def __init__(self):
        self.root = XmlField('FileHeader')
        self.schemaversion = XmlField('SchemaVersion')
        self.modality = XmlField('Modality')
        self.invoiceissuertype = XmlField('InvoiceIssuerType')
        self.batch = Batch()
        super(FileHeader, self).__init__('FileHeader', 'root')

# 1.5


class Batch(XmlModel):

    _sort_order = ('batch', 'batchidentifier', 'invoicescount',
                   'totalinvoicesamount', 'totaloutstandingamount',
                   'totalexecutableamount', 'invoicecurrencycode')

    def __init__(self):
        self.batch = XmlField('Batch')
        self.batchidentifier = XmlField('BatchIdentifier')
        self.invoicescount = XmlField('InvoicesCount')
        self.totalinvoicesamount = Totals('TotalInvoicesAmount')
        self.totaloutstandingamount = Totals('TotalOutstandingAmount')
        self.totalexecutableamount = Totals('TotalExecutableAmount')
        self.invoicecurrencycode = XmlField('InvoiceCurrencyCode')
        super(Batch, self).__init__('Batch', 'batch')

# 1.5.3
# 1.5.4
# 1.5.5


class Totals(XmlModel):

    _sort_order = ('total', 'totalamount', 'equivalentineuros')

    def __init__(self, tag):
        self.total = XmlField(tag)
        self.totalamount = XmlField('TotalAmount',
                                    rep=lambda x: '%.2f' % x)
        self.equivalentineuros = XmlField('EquivalentInEuros',
                                          rep=lambda x: '%.2f' % x)
        super(Totals, self).__init__(tag, 'total')

# 2


class Parties(XmlModel):

    _sort_order = ('parties', 'sellerparty', 'buyerparty')

    def __init__(self):
        self.parties = XmlField('Parties')
        self.sellerparty = Party('SellerParty')
        self.buyerparty = Party('BuyerParty')
        super(Parties, self).__init__('Parties', 'parties')

# 2.1
# 2.2


class Party(XmlModel):

    _sort_order = ('party', 'taxidentification',
                   'administrativecentres', 'legalentity')

    def __init__(self, tag):
        self.party = XmlField(tag)
        self.taxidentification = TaxIdentification()
        self.administrativecentres = AdministrativeCentres()
        self.legalentity = LegalEntity()
        super(Party, self).__init__(tag, 'party')

# 2.1.1


class TaxIdentification(XmlModel):

    _sort_order = ('taxidentification', 'persontypecode',
                   'residencetypecode', 'taxidentificationnumber')

    def __init__(self):
        self.taxidentification = XmlField('TaxIdentification')
        self.persontypecode = XmlField('PersonTypeCode')
        self.residencetypecode = XmlField('ResidenceTypeCode')
        self.taxidentificationnumber = XmlField('TaxIdentificationNumber')
        super(TaxIdentification, self).__init__('TaxIdentification',
                                                'taxidentification')

# 2.1.4.1


class LegalEntity(XmlModel):

    _sort_order = ('legalentity', 'corporatename',
                   'tradename', 'addressinspain')

    def __init__(self):
        self.legalentity = XmlField('LegalEntity')
        self.corporatename = XmlField('CorporateName')
        self.tradename = XmlField('TradeName')
        self.addressinspain = AddressInSpain()
        self.contactdetails = ContactDetails()
        super(LegalEntity, self).__init__('LegalEntity',
                                          'legalentity')

# 2.1.4.1.4.1


class AddressInSpain(XmlModel):

    _sort_order = ('addressinspain', 'address', 'postcode',
                   'town', 'province', 'countrycode')

    def __init__(self):
        self.addressinspain = XmlField('AddressInSpain')
        self.address = XmlField('Address', rep=lambda x: x[:80])
        self.postcode = XmlField('PostCode')
        self.town = XmlField('Town', rep=lambda x: x[:50])
        self.province = XmlField('Province', rep=lambda x: x[:20])
        self.countrycode = XmlField('CountryCode')
        super(AddressInSpain, self).__init__('AddressInSpain',
                                             'addressinspain')

# 2.1.4.1.5


class ContactDetails(XmlModel):

    _sort_order = ('contactdetails', 'telephone', 'telefax', 'webaddress',
                   'electronicmail', 'contactpersons', 'cnocnae',
                   'inetowncode', 'additionalcontactdetails')

    def __init__(self):
        self.contactdetails = XmlField('ContactDetails')
        self.telephone = XmlField('Telephone')
        self.telefax = XmlField('TeleFax')
        self.webaddress = XmlField('WebAddress')
        self.electronicmail = XmlField('ElectronicMail', rep=lambda x: x[:60])
        self.contactpersons = XmlField('ContactPersons')
        self.cnocnae = XmlField('CnoCnae')
        self.inetowncode = XmlField('INETownCode')
        self.additionalcontactdetails = XmlField('AdditionalContactDetails')
        super(ContactDetails, self).__init__('ContactDetails',
                                             'contactdetails')

# 2.2.3


class AdministrativeCentres(XmlModel):

    _sort_order = ('administrativecentres', 'administrativecentre')

    def __init__(self):
        self.administrativecentres = XmlField('AdministrativeCentres')
        self.administrativecentre = []  # List of AdministrativeCentre
        super(AdministrativeCentres, self).__init__('AdministrativeCentres',
                                                    'administrativecentres')

# 2.2.3.1


class AdministrativeCentre(XmlModel):

    _sort_order = ('administrativecentre', 'centrecode', 'roletypecode',
                   'name', 'firstsurname', 'secondsurname', 'addressinspain',
                   'contactdetails', 'centredescription')

    def __init__(self):
        self.administrativecentre = XmlField('AdministrativeCentre')
        self.centrecode = XmlField('CentreCode')
        self.roletypecode = XmlField('RoleTypeCode')
        self.name = XmlField('Name')
        self.firstsurname = XmlField('FirstSurname')
        self.secondsurname = XmlField('SecondSurname')
        self.addressinspain = AddressInSpain()
        self.contactdetails = ContactDetails()
        self.centredescription = XmlField('CentreDescription')
        super(AdministrativeCentre, self).__init__('AdministrativeCentre',
                                                   'administrativecentre')

# 3


class Invoices(XmlModel):

    _sort_order = ('invoices', 'invoice')

    def __init__(self):
        self.invoices = XmlField('Invoices')
        self.invoice = []
        super(Invoices, self).__init__('Invoices', 'invoices')

# 3.1


class Invoice(XmlModel):

    _sort_order = ('invoice', 'invoiceheader', 'invoiceissuedata',
                   'taxesoutputs', 'taxeswithhelds', 'invoicetotals',
                   'items', 'paymentdetails', 'legalliterals',
                   'additionaldata')

    def __init__(self):
        self.invoice = XmlField('Invoice')
        self.invoiceheader = InvoiceHeader()
        self.invoiceissuedata = InvoiceIssueData()
        self.taxesoutputs = Taxes('TaxesOutputs')
        self.taxeswithhelds = Taxes('TaxesWithhelds')
        self.invoicetotals = InvoiceTotals()
        self.items = Items()
        self.paymentdetails = PaymentDetails()
        self.legalliterals = LegalLiterals()
        self.additionaldata = AdditionalData()
        super(Invoice, self).__init__('Invoice', 'invoice')

# 3.1.1


class InvoiceHeader(XmlModel):

    _sort_order = ('invoice_header', 'invoicenumber', 'invoiceseriescode',
                   'invoicedocumenttype', 'invoiceclass', 'corrective')

    def __init__(self):
        self.invoiceheader = XmlField('InvoiceHeader')
        self.invoicenumber = XmlField('InvoiceNumber')
        self.invoiceseriescode = XmlField('InvoiceSeriesCode')
        self.invoicedocumenttype = XmlField('InvoiceDocumentType')
        self.invoiceclass = XmlField('InvoiceClass')
        self.corrective = Corrective()
        super(InvoiceHeader, self).__init__('InvoiceHeader', 'invoiceheader')

# 3.1.1.5


class Corrective(XmlModel):

    _sort_order = ('corrective', 'invoicenumber', 'invoiceseriescode',
                   'reasoncode', 'reasondescription', 'taxperiod',
                   'correctionmethod', 'correctionmethoddescription',
                   'additionalreasondescription', 'invoiceissuedate')

    def __init__(self):
        self.corrective = XmlField('Corrective')
        self.invoicenumber = XmlField('InvoiceNumber')
        self.invoiceseriescode = XmlField('InvoiceSeriesCode')
        self.reasoncode = XmlField('ReasonCode')
        self.reasondescription = XmlField('ReasonDescription')
        self.taxperiod = TaxPeriod()
        self.correctionmethod = XmlField('CorrectionMethod')
        self.correctionmethoddescription = XmlField('CorrectionMethodDescription')
        self.additionalreasondescription = XmlField('AdditionalReasonDescription')
        self.invoiceissuedate = XmlField('InvoiceIssueDate')
        super(Corrective, self).__init__('Corrective', 'corrective')

# 3.1.1.5.5


class TaxPeriod(XmlModel):

    _sort_order = ('taxperiod', 'startdate', 'enddate')

    def __init__(self):
        self.taxperiod = XmlField('TaxPeriod')
        self.startdate = XmlField('StartDate')
        self.enddate = XmlField('EndDate')
        super(TaxPeriod, self).__init__('TaxPeriod', 'taxperiod')

# 3.1.2


class InvoiceIssueData(XmlModel):

    _sort_order = ('invoiceissuedata', 'issuedate', 'operationdate',
                   'placeofissue', 'invoicingperiod', 'invoicecurrencycode',
                   'exchangeratedetails', 'taxcurrencycode', 'languagename',
                   'invoicedescription', 'receivertransactionreference',
                   'filereference', 'receivercontractreference')

    def __init__(self):
        self.invoiceissuedata = XmlField('InvoiceIssueData')
        self.issuedate = XmlField('IssueDate')
        self.operationdate = XmlField('OperationDate')
        self.placeofissue = PlaceOfIssue()
        self.invoicingperiod = InvoicingPeriod()
        self.invoicecurrencycode = XmlField('InvoiceCurrencyCode')
        self.exchangeratedetails = ExchangeRateDetails()
        self.taxcurrencycode = XmlField('TaxCurrencyCode')
        self.languagename = XmlField('LanguageName')
        self.invoicedescription = XmlField('InvoiceDescription')
        self.receivertransactionreference = XmlField('ReceiverTransactionReference')
        self.filereference = XmlField('FileReference')
        self.receivercontractreference = XmlField('ReceiverContractReference')

        super(InvoiceIssueData, self).__init__('InvoiceIssueData',
                                               'invoiceissuedata')

# 3.1.2.3


class PlaceOfIssue(XmlModel):

    _sort_order = ('placeofissue', 'postcode', 'placeofissuedescription')

    def __init__(self):
        self.placeofissue = XmlField('PlaceOfIssue')
        self.postcode = XmlField('PostCode')
        self.placeofissuedescription = XmlField('PlaceOfIssueDescription')
        super(PlaceOfIssue, self).__init__('PlaceOfIssue',
                                           'placeofissue')

# 3.1.2.4


class InvoicingPeriod(XmlModel):

    _sort_order = ('invoicingperiod', 'startdate', 'enddate')

    def __init__(self):
        self.invoicingperiod = XmlField('InvoicingPeriod')
        self.startdate = XmlField('StartDate')
        self.enddate = XmlField('EndDate')
        super(InvoicingPeriod, self).__init__('InvoicingPeriod',
                                              'invoicingperiod')

# 3.1.2.6


class ExchangeRateDetails(XmlModel):

    _sort_order = ('exchangeratedetails', 'exchangerate', 'exchangeratedate')

    def __init__(self):
        self.exchangeratedetails = XmlField('ExchangeRateDetails')
        self.exchangerate = XmlField('ExchangeRate')
        self.exchangeratedate = XmlField('ExchangeRateDate')
        super(ExchangeRateDetails, self).__init__('ExchangeRateDetails',
                                                  'exchangeratedetails')

# 3.1.3
# 3.1.4


class Taxes(XmlModel):

    _sort_order = ('taxes', 'tax')

    def __init__(self, tag):
        self.taxes = XmlField(tag)
        self.tax = []
        super(Taxes, self).__init__(tag, 'taxes')

# 3.1.3.1


class Tax(XmlModel):

    _sort_order = ('tax', 'taxtypecode', 'taxrate', 'taxablebase',
                   'taxamount', 'specialtaxablebase', 'specialtaxamount',
                   'equivalencesurcharge', 'equivalencesurchargeamount')

    def __init__(self):
        self.tax = XmlField('Tax')
        self.taxtypecode = XmlField('TaxTypeCode')
        self.taxrate = XmlField('TaxRate', rep=lambda x: '%.8f' % x)
        self.taxablebase = TaxData('TaxableBase')
        self.taxamount = TaxData('TaxAmount')
        self.specialtaxablebase = TaxData('SpecialTaxableBase')
        self.specialtaxamount = TaxData('SpecialTaxAmount')
        self.equivalencesurcharge = XmlField('EquivalenceSurcharge')
        self.equivalencesurchargeamount = TaxData('EquivalenceSurchargeAmount')
        super(Tax, self).__init__('Tax', 'tax')

# 3.1.3.1.3
# 3.1.3.1.4
# 3.1.3.1.5
# 3.1.3.1.6
# 3.1.3.1.8


class TaxData(XmlModel):

    _sort_order = ('taxdata', 'totalamount', 'equivalentineuros')

    def __init__(self, tag):
        self.taxdata = XmlField(tag)
        self.totalamount = XmlField('TotalAmount', rep=lambda x: '%.2f' % x)
        self.equivalentineuros = XmlField('EquivalentInEuros',
                                          rep=lambda x: '%.2f' % x)
        super(TaxData, self).__init__(tag, 'taxdata')

# 3.1.5


class InvoiceTotals(XmlModel):

    _sort_order = ('invoicetotals', 'totalgrossamount', 'generaldiscounts',
                   'generalsurcharges', 'totalgeneraldiscounts',
                   'totalgeneralsurcharges', 'totalgrossamountbeforetaxes',
                   'totaltaxoutputs', 'totaltaxeswithheld', 'invoicetotal',
                   'subsidies', 'totalfinancialexpenses',
                   'totaloutstandingamount', 'totalpaymentsonaccount',
                   'amountswithheld', 'totalexecutableamount',
                   'totalreinbursableexpenses', 'paymentinkind')

    def __init__(self):
        self.invoicetotals = XmlField('InvoiceTotals')
        self.totalgrossamount = XmlField('TotalGrossAmount',
                                         rep=lambda x: '%.2f' % x)
        self.generaldiscounts = GeneralDiscounts('GeneralDiscounts')
        self.generalsurcharges = GeneralDiscounts('GeneralSurcharges')
        self.totalgeneraldiscounts = XmlField('TotalGeneralDiscounts')
        self.totalgeneralsurcharges = XmlField('TotalGeneralSurcharges')
        self.totalgrossamountbeforetaxes = XmlField(
                                            'TotalGrossAmountBeforeTaxes',
                                            rep=lambda x: '%.2f' % x)
        self.totaltaxoutputs = XmlField('TotalTaxOutputs',
                                        rep=lambda x: '%.2f' % x)
        self.totaltaxeswithheld = XmlField('TotalTaxesWithheld',
                                            rep=lambda x: '%.2f' % x)
        self.invoicetotal = XmlField('InvoiceTotal',
                                     rep=lambda x: '%.2f' % x)
        self.subsidies = Subsidies()
        self.paymentsonaccount = PaymentsOnAccount()
        self.reinbursableexpenses = ReinbursableExpenses()
        self.totalfinancialexpenses = XmlField('TotalFinancialExpenses')
        self.totaloutstandingamount = XmlField('TotalOutstandingAmount',
                                               rep=lambda x: '%.2f' % x)
        self.totalpaymentsonaccount = XmlField('TotalPaymentsOnAccount')
        self.amountswithheld = AmountsWithheld()
        self.totalexecutableamount = XmlField('TotalExecutableAmount',
                                              rep=lambda x: '%.2f' % x)
        self.totalreimbursableexpenses = XmlField('TotalReimbursableExpenses')
        self.paymentinkind = PaymentInKind()
        super(InvoiceTotals, self).__init__('InvoiceTotals',
                                            'invoicetotals')

#3.1.5.2


class GeneralDiscounts(XmlModel):

    _sort_order = ('generaldiscounts', 'discount')

    def __init__(self, tag):
        self.generaldiscounts = XmlField(tag)
        self.discount = []
        super(GeneralDiscounts, self).__init__(tag,
                                               'generaldiscounts')

# 3.1.5.2.1


class Discount(XmlModel):

    _sort_order = ('discount', 'discountreason',
                   'discountrate', 'discountamount')

    def __init__(self):
        self.discount = XmlField('Discount')
        self.discountreason = XmlField('DiscountReason')
        self.discountrate = XmlField('DiscountRate')
        self.discountamount = XmlField('DiscountAmount')
        super(Discount, self).__init__('Discount', 'discount')

# 3.1.5.3


class GeneralSurcharges(XmlModel):

    _sort_order = ('generalsurcharges', 'charge')

    def __init__(self, tag):
        self.generalsurcharges = XmlField(tag)
        self.charge = []
        super(GeneralSurcharges, self).__init__(tag,
                                                'generalsurcharges')

# 3.1.5.3.1


class Charge(XmlModel):

    _sort_order = ('charge', 'chargereason', 'chargerate', 'chargeamount')

    def __init__(self):
        self.charge = XmlField('Charge')
        self.chargereason = XmlField('ChargeReason')
        self.chargerate = XmlField('ChargeRate')
        self.chargeamount = XmlField('ChargeAmount')
        super(Charge, self).__init__('Charge', 'charge')

# 3.1.5.10


class Subsidies(XmlModel):

    _sort_order = ('subsudies', 'subsidy')

    def __init__(self):
        self.subsidies = XmlField('Subsidies')
        self.subsidy = []
        super(Subsidies, self).__init__('Subsidies', 'subsidies')

# 3.1.5.10.1


class Subsidy(XmlModel):

    _sort_order = ('subsidy', 'subsidydescription',
                   'subsidyrate', 'subsidyamount')

    def __init__(self):
        self.subsidy = XmlField('Subsidy')
        self.subsidydescription = XmlField('SubsidyDescription')
        self.subsidyrate = XmlField('SubsidyRate')
        self.subsidyamount = XmlField('SubsidyAmount')
        super(Subsidy, self).__init__('Subsidy', 'subsidy')

# 3.1.5.11


class PaymentsOnAccount(XmlModel):

    _sort_order = ('paymentsonaccount', 'paymentonaccount')

    def __init__(self):
        self.paymentsonaccount = XmlField('PaymentsOnAccount')
        self.paymentonaccount = []
        super(PaymentsOnAccount, self).__init__('PaymentsOnAccount',
                                                'paymentsonaccount')

# 3.1.5.11.1


class PaymentOnAccount(XmlModel):

    _sort_order = ('paymentonaccount', 'paymentonaccountdate',
                   'paymentonaccountamount')

    def __init__(self):
        self.paymentonaccount = XmlField('PaymentOnAccount')
        self.paymentonaccountdate = XmlField('PaymentOnAccountDate')
        self.paymentonaccountamount = XmlField('PaymentOnAccountAmount')
        super(PaymentOnAccount, self).__init__('PaymentOnAccount',
                                               'paymentonaccount')

# 3.1.5.12


class ReinbursableExpenses(XmlModel):

    _sort_order = ('reinbursableexpenses', 'reinbursableexpens')

    def __init__(self):
        self.reinbursableexpenses = XmlField('ReinbursableExpenses')
        self.reinbursableexpens = []
        super(ReinbursableExpenses, self).__init__('ReinbursableExpenses',
                                                   'reinbursableexpenses')

# 3.1.5.12.1


class ReinbursableExpens(XmlModel):

    _sort_order = ('reinbursableexpens', 'reinbursableexpensessellerparty',
                   'reinbursableexpensesbuyerparty', 'issuedate',
                   'invoicenumber', 'invoiceseriescode',
                   'reinbursableexpensesamount')

    def __init__(self):
        self.reinbursableexpens = XmlField('ReinbursableExpenses')
        self.reinbursableexpensessellerparty = ReinbursableExpensesParty(
                                            'ReinbursableExpensesSellerParty')
        self.reinbursableexpensesbuyerparty = ReinbursableExpensesParty(
                                            'ReinbursableExpensesBuyerParty')
        self.issuedate = XmlField('IssueDate')
        self.invoicenumber = XmlField('InvoiceNumber')
        self.invoiceseriescode = XmlField('InvoiceSeriesCode')
        self.reinbursableexpensesamount = XmlField(
                                            'ReinbursableExpensesAmount')
        super(ReinbursableExpens, self).__init__('ReinbursableExpenses',
                                                 'reinbursableexpens')

# 3.1.5.12.1.1
# 3.1.5.12.1.2


class ReinbursableExpensesParty(XmlModel):

    _sort_order = ('reinbursableexpensesparty', 'persontypecode',
                   'residenctypecode', 'taxidentificationnumber')

    def __init__(self, tag):
        self.reinbursableexpensesparty = XmlField(tag)
        self.persontypecode = XmlField('PersonTypeCode')
        self.residencetypecode = XmlField('ResidenceTypeCode')
        self.taxidentificationnumber = XmlField('TaxIdentificationNumber')
        super(ReinbursableExpensesParty,
              self).__init__(tag, 'reinbursableexpensesparty')

# 3.1.5.16


class AmountsWithheld(XmlModel):

    _sort_order = ('amountswithheld', 'withholdingreason',
                   'withholdingrate', 'withholdingamount')

    def __init__(self):
        self.amountswithheld = XmlField('AmountsWithheld')
        self.withholdingreason = XmlField('WithholdingReason')
        self.withholdingrate = XmlField('WithholdingRate')
        self.withholdingamount = XmlField('WithholdingAmount')
        super(AmountsWithheld, self).__init__('AmountsWithheld',
                                              'amountswithheld')

# 3.1.5.19


class PaymentInKind(XmlModel):

    _sort_order = ('paymentinkind', 'paymentinkindreason', 'paymentinkindamount')

    def __init__(self):
        self.paymentinkind = XmlField('PaymentInKind')
        self.paymentinkindreason = XmlField('PaymentInKindReason')
        self.paymentinkindamount = XmlField('PaymentInKindAmount')
        super(PaymentInKind, self).__init__('PaymentInKind',
                                              'paymentinkind')

# 3.1.6


class Items(XmlModel):

    _sort_order = ()

    def __init__(self):
        self.items = XmlField('Items')
        self.invoiceline = []
        super(Items, self).__init__('Items', 'items')

# 3.1.6.1


class InvoiceLine(XmlModel):

    _sort_order = ('invoiceline', 'issuercontractreference',
                   'issuercontractdate', 'issuertransactionreference',
                   'issuertransactiondate', 'receivercontractreference',
                   'receivercontractdate', 'receivertransactionreference',
                   'receivertransactiondate', 'filereference',
                   'sequencenumber', 'deliverynotesreference',
                   'itemdescription', 'quantity', 'unitofmeasure',
                   'unitpricewithouttax', 'totalcost',
                   'discountandrebates', 'charges', 'grossamount',
                   'taxeswithheld', 'taxesoutputs', 'lineitemperiod',
                   'transactiondate', 'additionallineiteminformation',
                   'specialtaxableevent', 'articlecode')

    def __init__(self):
        self.invoiceline = XmlField('InvoiceLine')
        self.issuercontractreference = XmlField('IssuerContractReference')
        self.issuercontractdate = XmlField('IssuerContractDate')
        self.issuertransactionreference = XmlField(
                                            'IssuerTransactionReference')
        self.issuertransactiondate = XmlField('IssuerTransactionDate')
        self.receivercontractreference = XmlField('ReceiverContractReference')
        self.receivercontractdate = XmlField('ReceiverContractDate')
        self.receivertransactionreference = XmlField(
                                            'ReceiverTransactionReference')
        self.receivertransactiondate = XmlField('ReceiverTransactionDate')
        self.filereference = XmlField('FileReference')
        self.sequencenumber = XmlField('SequenceNumber')
        self.deliverynotesreference = DeliveryNotesReference()
        self.itemdescription = XmlField('ItemDescription')
        self.quantity = XmlField('Quantity', rep=lambda x: '%.8f' % x)
        self.unitofmeasure = XmlField('UnitOfMeasure')
        self.unitpricewithouttax = XmlField('UnitPriceWithoutTax',
                                            rep=lambda x: '%.8f' % x)
        self.totalcost = XmlField('TotalCost', rep=lambda x: '%.8f' % x)
        self.discountandrebates = GeneralDiscounts('DiscountsAndRebates')
        self.charges = GeneralSurcharges('Charges')
        self.grossamount = XmlField('GrossAmount', rep=lambda x: '%.8f' % x)
        self.taxeswithheld = Taxes('TaxesWithheld')
        self.taxesoutputs = Taxes('TaxesOutputs')
        self.lineitemperiod = LineItemPeriod()
        self.transactiondate = XmlField('TransactionDate')
        self.additionallineiteminformation = XmlField(
                                            'AdditionalLineItemInformation')
        self.specialtaxableevent = SpecialTaxableEvent()
        self.articlecode = XmlField('ArticleCode')
        super(InvoiceLine, self).__init__('InvoiceLine', 'invoiceline')

# 3.1.6.1.12


class DeliveryNotesReference(XmlModel):

    _sort_order = ('deliverynotesreference', 'deliverynote')

    def __init__(self):
        self.deliverynotesreference = XmlField('DeliveryNotesReference')
        self.deliverynote = []
        super(DeliveryNotesReference, self).__init__('DeliveryNotesReference',
                                                     'deliverynotesreference')

# 3.1.6.1.12.1


class DeliveryNote(XmlModel):

    _sort_order = ('deliverynote', 'deliverynotenumber',
                   'deliverynotedate')

    def __init__(self):
        self.deliverynote = XmlField('DeliveryNote')
        self.deliverynotenumber = XmlField('DeliveryNoteNumber')
        self.deliverynotedate = XmlField('DeliveryNoteDate')
        super(DeliveryNote, self).__init__('DeliveryNote',
                                           'deliverynote')

# 3.1.6.1.23


class LineItemPeriod(XmlModel):

    _sort_order = ('lineitemperiod', 'startdate', 'enddate')

    def __init__(self):
        self.lineitemperiod = XmlField('LineItemPeriod')
        self.startdate = XmlField('StartDate')
        self.enddate = XmlField('EndDate')
        super(LineItemPeriod, self).__init__('LineItemPeriod',
                                             'lineitemperiod')

# 3.1.6.1.26


class SpecialTaxableEvent(XmlModel):

    _sort_order = ('specialtaxableevent', 'specialtaxableeventcode',
                   'specialtaxableeventreason')

    def __init__(self):
        self.specialtaxableevent = XmlField('SpecialTaxableEvent')
        self.specialtaxableeventcode = XmlField('SpecialTaxableEventCode')
        self.specialtaxableeventreason = XmlField('SpecialTaxableEventReason')
        super(SpecialTaxableEvent, self).__init__('SpecialTaxableEvent',
                                                  'specialtaxableevent')

# 3.1.7


class PaymentDetails(XmlModel):

    _sort_order = ('paymentdetails', 'installment')

    def __init__(self):
        self.paymentdetails = XmlField('PaymentDetails')
        self.installment = []
        super(PaymentDetails, self).__init__('PaymentDetails',
                                             'paymentdetails')

# 3.1.7.1


class Installment(XmlModel):

    _sort_order = ('installment', 'installmentduedate', 'installmentamount',
                   'paymentmeans', 'accounttobecredited',
                   'paymentreconciliationreference', 'accounttobedebited',
                   'collectionadditionalinformation',
                   'regulatoryreportingdata', 'debitreconciliationreference')

    def __init__(self):
        self.installment = XmlField('Installment')
        self.installmentduedate = XmlField('InstallmentDueDate')
        self.installmentamount = XmlField('InstallmentAmount',
                                          rep=lambda x: '%.2f' % x)
        self.paymentmeans = XmlField('PaymentMeans')
        self.accounttobecredited = Account('AccountToBeCredited')
        self.paymentreconciliationreference = XmlField(
                                            'PaymentReconciliationReference')
        self.accounttobedebited = Account('AccountToBeDebited')
        self.collectionadditionalinformation = XmlField(
                                            'CollectionAdditionalInformation')
        self.regulatoryreportingdata = XmlField('RegulatoryReportingData')
        self.debitreconciliationreference = XmlField(
                                            'DebitReconciliationReference')
        super(Installment, self).__init__('Installment', 'installment')

# 3.1.7.1.4


class Account(XmlModel):

    _sort_order = ('account', 'iban', 'bankcode', 'branchcode', 'bic')

    def __init__(self, tag):
        self.account = XmlField(tag)
        self.iban = XmlField('IBAN')
        self.bankcode = XmlField('BankCode')
        self.branchcode = XmlField('BranchCode')
        self.bic = XmlField('BIC')
        super(Account, self).__init__(tag, 'account')

# 3.1.8


class LegalLiterals(XmlModel):

    _sort_order = ('legalliterals', 'legalreference')

    def __init__(self):
        self.legalliterals = XmlField('LegalLiterals')
        self.legalreference = []
        super(LegalLiterals, self).__init__('LegalLiterals',
                                            'legalliterals')

# 3.1.8.1


class LegalReference(XmlModel):

    _sort_order = ('legalreference')

    def __init__(self):
        self.legalreference = XmlField('LegalReference')
        super(LegalReference, self).__init__('LegalReference',
                                             'legalreference')

# 3.1.9


class AdditionalData(XmlModel):

    _sort_order = ('additionaldata', 'relatedinvoice', 'relateddocuments',
                   'invoiceadditionalinformation', 'extensions')

    def __init__(self):
        self.additionaldata = XmlField('AdditionalData')
        self.relatedinvoice = XmlField('RelatedInvoice')
        self.relateddocuments = RelatedDocuments()
        self.invoiceadditionalinformation = XmlField(
                                            'InvoiceAdditionalInformation')
        self.extensions = XmlField('Extensions')
        super(AdditionalData, self).__init__('AdditionalData',
                                             'additionaldata')

# 3.1.9.2


class RelatedDocuments(XmlModel):

    _sort_order = ('relateddocuments', 'attachment')

    def __init__(self):
        self.relateddocuments = XmlField('RelatedDocuments')
        self.attachment = []
        super(RelatedDocuments, self).__init__('RelatedDocuments',
                                               'relateddocuments')

# 3.1.9.2.1


class Attachment(XmlModel):

    _sort_order = ('attachment', 'attachmentcompressionalgorithm',
                   'attachmentformat', 'attachmentencoding',
                   'attachmentdescription', 'attachmentdata')

    def __init__(self):
        self.attachment = XmlField('Attachment')
        self.attachmentcompressionalgorithm = XmlField(
                                            'AttachmentCompressionAlgorithm')
        self.attachmentformat = XmlField('AttachmentFormat')
        self.attachmentencoding = XmlField('AttachmentEncoding')
        self.attachmentdescription = XmlField('AttachmentDescription')
        self.attachmentdata = XmlField('AttachmentData')
        super(Attachment, self).__init__('Attachment',
                                         'attachment')
