# -*- coding: utf-8 -*-

from libcomxml.core import XmlModel, XmlField
from .utils import FacturaeUtils
from signxml import XMLSigner, XMLVerifier
from xml.etree import ElementTree


class Extensions(XmlModel):

    _sort_order = ('extensions', 'utilities')

    def __init__(self):
        self.extensions = XmlField('Extensions')
        self.utilities = []
        super(Extensions, self).__init__('Extensions', 'extensions')

# 2.2


class UtilitiesExtensionsELE(XmlModel):

    _sort_order = ('utilitiesextensionsele', 'version', 'utilitiesfacturaresumen', 'utilitiesextensionele')

    def __init__(self):
        self.utilitiesextensionsele = XmlField('UtilitiesExtensionsELE')
        self.version = XmlField('Version')
        self.utilitiesfacturaresumen = UtilitiesFacturaResumen()
        self.utilitiesextensionele = UtilitiesExtensionELE()
        super(UtilitiesExtensionsELE, self).__init__('UtilitiesExtensionsELE', 'utilitiesextensionsele')

# 2.2


class UtilitiesFacturaResumen(XmlModel):

    _sort_order = ('utilitiesfacturaresumen','facturaresumen', 'conceptosfr', 'totalantesimpuestos', 'impuestosfr')

    def __init__(self):
        self.utilitiesfacturaresumen = XmlField('UtilitiesFacturaResumen')
        self.facturaresumen = XmlField('FacturaResumen')
        self.conceptosfr = ConceptosFR()
        self.totalantesimpuestos = XmlField('TotalAntesImpuestos')
        self.impuestosfr = ImpuestosFR()
        super(UtilitiesFacturaResumen, self).__init__('UtilitiesFacturaResumen', 'utilitiesfacturaresumen')

# 2.2


class ConceptosFR(XmlModel):

    _sort_order = ('conceptosfr', 'conceptofr', )

    def __init__(self):
        self.conceptosfr = XmlField('ConceptosFR')
        self.conceptofr = []
        super(ConceptosFR, self).__init__('ConceptosFR', 'conceptosfr')

# 2.2


class ConceptoFR(XmlModel):

    _sort_order = ('conceptofacturadofr', 'tipoconceptofacturadofr', 'importe')

    def __init__(self):
        self.conceptofacturadofr = XmlField('ConceptoFacturadoFR')
        self.tipoconceptofacturadofr = XmlField('TipoConceptoFacturadoFR')
        self.importe = XmlField('Importe')
        super(ConceptoFR, self).__init__('ConceptoFR', 'conceptofr')

# 2.2


class ImpuestosFR(XmlModel):

    _sort_order = ('impuestosfr', 'impuesto')

    def __init__(self):
        self.impuestosfr = XmlField('ImpuestosFR')
        self.impuesto = []
        super(ImpuestosFR, self).__init__('ImpuestosFR', 'impuestosfr')

# 2.2


class Impuesto(XmlModel):

    _sort_order = ('impuesto', 'base', 'tipoimpuesto', 'tipoimpositivo', 'tipooperacion', 'importe')

    def __init__(self):
        self.impuesto = XmlField('Impuesto')
        self.base = XmlField('Base')
        self.tipoimpuesto = XmlField('TipoImpuesto')
        self.tipoimpositivo = XmlField('TipoImpositivo')
        self.tipooperacion = XmlField('TipoOperacion')
        self.importe = XmlField('Importe')
        super(Impuesto, self).__init__('Impuesto', 'impuesto')

# 2.2


class UtilitiesExtensionELE(XmlModel):

    _sort_order = ('utilitiesextensionele', 'tipoextension', 'datosdelsuministro', 'utilitiesmedida', 'utilitiesdesgloseconceptosfactura'
                   , 'utilitieshistoricoconsumos', 'utilitiesmensajes', 'utilitiesatrasociado', 'utilitiescurva')

    def __init__(self):
        self.utilitiesextensionele = XmlField('UtilitiesExtensionELE')
        self.tipoextension = XmlField('TipoExtension')
        self.datosdelsuministro = DatosDelSuministro()
        self.utilitiesmedida = UtilitiesMedida()
        self.utilitiesdesgloseconceptosfactura = UtilitiesDesgloseConceptosFactura()
        self.utilitieshistoricoconsumos = UtilitiesHistoricoConsumos()
        self.utilitiesmensajes = UtilitiesMensajes()
        self.utilitiesatrasociado = UtilitiesAtrAsociado()
        self.utilitiescurva = UtilitiesCurva()
        super(UtilitiesExtensionELE, self).__init__('UtilitiesExtensionELE', 'utilitiesextensionele')

# 2.2


class DatosDelSuministro(XmlModel):

    _sort_order = ('datosdelsuministro', 'cups', 'direccionsuministro', 'contrato', 'potenciascontratadas',
                   'datosdistribuidora', 'referenciaslegal', 'tarifa', 'agrupacion', 'referencia')

    def __init__(self):
        self.datosdelsuministro = XmlField('DatosDelSuministro')
        self.cups = XmlField('CUPS')
        self.direccionsuministro = DireccionSuministro()
        self.contrato = Contrato()
        self.potenciascontratadas = PotenciasContratadas()
        self.datosdistribuidora = DatosDistribuidora()
        self.referenciaslegal = ReferenciasLegal()
        self.tarifa = Tarifa()
        self.agrupacion = Agrupacion()
        self.referencia = XmlField('Referencia')
        super(DatosDelSuministro, self).__init__('DatosDelSuministro', 'datosdelsuministro')

# 2.2


class DireccionSuministro(XmlModel):

    _sort_order = ('direccionsuministro', 'direccion', 'codigopostal', 'poblacion', 'provincia', 'pais')

    def __init__(self):
        self.direccionsuministro = XmlField('DireccionSuministro')
        self.direccion = XmlField('Direccion')
        self.codigopostal = XmlField('CodigoPostal')
        self.poblacion = XmlField('Poblacion')
        self.provincia = XmlField('Provincia')
        self.pais = XmlField('Pais')
        super(DireccionSuministro, self).__init__('DireccionSuministro', 'direccionsuministro')

# 2.2


class Contrato(XmlModel):

    _sort_order = ('contrato', 'refcontratoempresa', 'fechafincontrato')

    def __init__(self):
        self.contrato = XmlField('Contrato')
        self.refcontratoempresa = XmlField('RefContratoEmpresa')
        self.fechafincontrato = XmlField('FechaFinContrato')
        super(Contrato, self).__init__('Contrato', 'contrato')

# 2.2


class PotenciasContratadas(XmlModel):

    _sort_order = ('potenciascontratadas', 'potenciacontratada')

    def __init__(self):
        self.potenciascontratadas = XmlField('PotenciasContratadas')
        self.potenciacontratada = []
        super(PotenciasContratadas, self).__init__('PotenciasContratadas', 'potenciascontratadas')

# 2.2


class PotenciaContratada(XmlModel):

    _sort_order = ('potenciacontratada', 'periodo', 'valor', 'unidadmedida', 'fechadesde', 'fechahasta')

    def __init__(self):
        self.potenciacontratada = XmlField('PotenciaContratada')
        self.periodo = XmlField('Periodo')
        self.valor = XmlField('Valor')
        self.unidadmedida = XmlField('UnidadMedida')
        self.fechadesde = XmlField('FechaDesde')
        self.fechahasta = XmlField('FechaHasta')
        super(PotenciaContratada, self).__init__('PotenciaContratada', 'potenciacontratada')

# 2.2


class DatosDistribuidora(XmlModel):

    _sort_order = ('datosdistribuidora', 'distribuidora', 'telefonoaverias')

    def __init__(self):
        self.datosdistribuidora = XmlField('DatosDistribuidora')
        self.distribuidora = XmlField('Distribuidora')
        self.telefonoaverias = XmlField('TelefonoAverias')
        super(DatosDistribuidora, self).__init__('DatosDistribuidora', 'datosdistribuidora')

# 2.2


class ReferenciasLegal(XmlModel):

    _sort_order = ('referenciaslegal', 'referencialegal')

    def __init__(self):
        self.referenciaslegal = XmlField('DatosDistribuidora')
        self.referencialegal = ReferenciaLegal()
        super(ReferenciasLegal, self).__init__('ReferenciasLegal', 'referenciaslegal')

# 2.2


class ReferenciaLegal(XmlModel):

    _sort_order = ('referencialegal', 'boeboca', 'fechaboeboca')

    def __init__(self):
        self.referencialegal = XmlField('ReferenciaLegal')
        self.boeboca = XmlField('BOEBOCA')
        self.fechaboeboca = XmlField('FechaBOEBOCA')
        super(ReferenciaLegal, self).__init__('ReferenciaLegal', 'referencialegal')

# 2.2


class Tarifa(XmlModel):

    _sort_order = ('tarifa', 'CodigoTarifaProducto', 'AltaMedidaEnBaja')

    def __init__(self):
        self.tarifa = XmlField('Tarifa')
        self.CodigoTarifaProducto = XmlField('CodigoTarifaProducto')
        self.AltaMedidaEnBaja = AltaMedidaEnBaja()
        super(Tarifa, self).__init__('Tarifa', 'tarifa')

# 2.2


class AltaMedidaEnBaja(XmlModel):

    _sort_order = ('altamedidaenbaja', 'marcamedidaconperdidas', 'kvastrafo', 'porcentajeperdidaspactadas')

    def __init__(self):
        self.altamedidaenbaja = XmlField('AltaMedidaEnBaja')
        self.marcamedidaconperdidas = XmlField('MarcaMedidaConPerdidas')
        self.kvastrafo = XmlField('KVAsTrafo')
        self.porcentajeperdidaspactadas = XmlField('PorcentajePerdidasPactadas')
        super(AltaMedidaEnBaja, self).__init__('AltaMedidaEnBaja', 'altamedidaenbaja')

# 2.2


class Agrupacion(XmlModel):

    _sort_order = ('agrupacion', 'codigoagrupacion')

    def __init__(self):
        self.agrupacion = XmlField('Agrupacion')
        self.codigoagrupacion = XmlField('CodigoAgrupacion')
        super(Agrupacion, self).__init__('Agrupacion', 'agrupacion')

# 2.2


class UtilitiesMedida(XmlModel):

    _sort_order = ('utilitiesmedida', 'medidassobreequipo')

    def __init__(self):
        self.utilitiesmedida = XmlField('UtilitiesMedida')
        self.medidassobreequipo = MedidasSobreEquipo()
        super(UtilitiesMedida, self).__init__('UtilitiesMedida', 'utilitiesmedida')

# 2.2


class MedidasSobreEquipo(XmlModel):

    _sort_order = ('medidassobreequipo', 'medidasobreequipo')

    def __init__(self):
        self.medidassobreequipo = XmlField('MedidasSobreEquipo')
        self.medidasobreequipo = []
        super(MedidasSobreEquipo, self).__init__('MedidasSobreEquipo', 'medidassobreequipo')

# 2.2


class MedidaSobreEquipo(XmlModel):
    _sort_order = ('medidasobreequipo', 'tipomedida', 'lineamedidacontador', 'numeroserie', 'codigodh',
                   'magnitud', 'constantemultiplicadora', 'lecturadesde', 'fechahoradesde', 'lecturahasta',
                   'fechahorahasta', 'tipodelecturadesde', 'tipodelecturahasta', 'consumoleido',
                   'unidadconsumoenergialeido', 'ajuste', 'consumocalculado', 'unidadconsumocalculado')

    def __init__(self):
        self.medidasobreequipo = XmlField('MedidaSobreEquipo')
        self.tipomedida = XmlField('TipoMedida')
        self.lineamedidacontador = XmlField('LineaMedidaContador')
        self.numeroserie = XmlField('NumeroSerie')
        self.codigodh = XmlField('CodigoDH')
        self.magnitud = XmlField('Magnitud')
        self.constantemultiplicadora = XmlField('ConstanteMultiplicadora')
        self.lecturadesde = XmlField('LecturaDesde')
        self.fechahoradesde = XmlField('FechaHoraDesde')
        self.lecturahasta = XmlField('LecturaHasta')
        self.fechahorahasta = XmlField('FechaHoraHasta')
        self.tipodelecturadesde = XmlField('TipoDeLecturaDesde')
        self.tipodelecturahasta = XmlField('TipoDeLecturaHasta')
        self.consumoleido = XmlField('ConsumoLeido')
        self.unidadconsumoenergialeido = XmlField('UnidadConsumoEnergiaLeido')
        self.ajuste = XmlField('Ajuste')
        self.consumocalculado = XmlField('ConsumoCalculado')
        self.unidadconsumocalculado = XmlField('UnidadConsumoCalculado')
        super(MedidaSobreEquipo, self).__init__('MedidaSobreEquipo', 'medidasobreequipo')

# 2.2


class UtilitiesDesgloseConceptosFactura(XmlModel):

    _sort_order = ('utilitiesdesgloseconceptosfactura', 'desgloseconceptosfactura', 'impuestos')

    def __init__(self):
        self.utilitiesdesgloseconceptosfactura = XmlField('UtilitiesDesgloseConceptosFactura')
        self.desgloseconceptosfactura = []
        self.impuestos = Impuestos()
        super(UtilitiesDesgloseConceptosFactura, self).__init__('UtilitiesDesgloseConceptosFactura', 'utilitiesdesgloseconceptosfactura')

# 2.2


class DesgloseConceptosFactura(XmlModel):

    _sort_order = ('desgloseconceptosfactura', 'conceptofacturado', 'tipoconceptofacturado', 'detalleperiodo')

    def __init__(self):
        self.desgloseconceptosfactura = XmlField('DesgloseConceptosFactura')
        self.conceptofacturado = XmlField('ConceptoFacturado')
        self.tipoconceptofacturado = XmlField('TipoConceptoFacturado')
        self.detalleperiodo = []

        super(DesgloseConceptosFactura, self).__init__('DesgloseConceptosFactura', 'desgloseconceptosfactura')

# 2.2

class DetallePeriodo(XmlModel):

    _sort_order = ('detalleperiodo', 'periododh', 'cantidad', 'unidadescantidad', 'fechadesde',
                   'fechahasta', 'periodo', 'unidadperiodo', 'preciounitario', 'unidadespreciounitario',
                   'lineasmedidacontador', 'importe')

    def __init__(self):
        self.detalleperiodo = XmlField('DetallePeriodo')
        self.periododh = XmlField('PeriodoDH')
        self.cantidad = XmlField('Cantidad')
        self.unidadescantidad = XmlField('UnidadesCantidad')
        self.fechadesde = XmlField('FechaDesde')
        self.fechahasta = XmlField('FechaHasta')
        self.periodo = XmlField('Periodo')
        self.unidadperiodo = XmlField('UnidadPeriodo')
        self.preciounitario = XmlField('PrecioUnitario')
        self.unidadespreciounitario = XmlField('UnidadesPrecioUnitario')
        self.lineasmedidacontador = LineasMedidaContador()
        self.importe = XmlField('Importe')
        super(DetallePeriodo, self).__init__('DetallePeriodo', 'detalleperiodo')

# 2.2


class LineasMedidaContador(XmlModel):

    _sort_order = ('lineasmedidacontador', 'lineamedidacontador_list')

    def __init__(self):
        self.lineasmedidacontador = XmlField('LineasMedidaContador')
        self.self.lineamedidacontador_list = []
        super(LineasMedidaContador, self).__init__('LineasMedidaContador', 'lineasmedidacontador', drop_empty=False)

# 2.2


class LineaMedidaContador(XmlModel):

    _sort_order = ('lineamedidacontador',)

    def __init__(self):
        self.lineamedidacontador = XmlField('LineaMedidaContador')
        super(LineaMedidaContador, self).__init__('LineaMedidaContador', 'lineamedidacontador', drop_empty=False)

# 2.2


class Impuestos(XmlModel):

    _sort_order = ('impuestos', 'impuesto')

    def __init__(self):
        self.impuestos = XmlField('Impuestos')
        self.impuesto = []
        super(Impuestos, self).__init__('Impuestos', 'impuestos')

# 2.2


class UtilitiesHistoricoConsumos(XmlModel):

    _sort_order = ('utilitieshistoricoconsumos', 'historicoconsumo')

    def __init__(self):
        self.utilitieshistoricoconsumos = XmlField('UtilitiesHistoricoConsumos')
        self.historicoconsumo = []
        super(UtilitiesHistoricoConsumos, self).__init__('UtilitiesHistoricoConsumos', 'utilitieshistoricoconsumos')

# 2.2


class HistoriCoconsumo(XmlModel):
    _sort_order = ('historicoconsumo', 'periodo', 'descripcion', 'valor', 'unidadmedida',
                   'fechadesdeperiodo', 'fechahastaperiodo')

    def __init__(self):
        self.historicoconsumo = XmlField('HistoricoConsumo')
        self.periodo = XmlField('Periodo')
        self.descripcion = XmlField('Descripcion')
        self.valor = XmlField('Valor')
        self.unidadmedida = XmlField('UnidadMedida')
        self.fechadesdeperiodo = XmlField('FechaDesdePeriodo')
        self.fechahastaperiodo = XmlField('FechaHastaPeriodo')
        super(HistoriCoconsumo, self).__init__('HistoriCoconsumo', 'historicoconsumo')

# 2.2


class UtilitiesMensajes(XmlModel):

    _sort_order = ('utilitiesmensajes', 'listamensajes')

    def __init__(self):
        self.utilitiesmensajes = XmlField('UtilitiesMensajes')
        self.listamensajes = ListaMensajes()
        super(UtilitiesMensajes, self).__init__('UtilitiesMensajes', 'utilitiesmensajes')

# 2.2


class ListaMensajes(XmlModel):

    _sort_order = ('listamensajes', 'mensaje')

    def __init__(self):
        self.listamensajes = XmlField('ListaMensajes')
        self.mensaje = []
        super(ListaMensajes, self).__init__('ListaMensajes', 'listamensajes')

# 2.2


class Mensaje(XmlModel):

    _sort_order = ('mensaje', 'mensajeid', 'contenido')

    def __init__(self):
        self.mensaje = XmlField('Mensaje')
        self.mensajeid = XmlField('MensajeID')
        self.contenido = XmlField('Contenido')
        super(Mensaje, self).__init__('Mensaje', 'mensaje')

# 2.2


class UtilitiesAtrAsociado(XmlModel):

    _sort_order = ('utilitiesatrasociado', 'tarifadeaccesoatr', 'contratodeacceso')

    def __init__(self):
        self.utilitiesatrasociado = XmlField('UtilitiesAtrAsociado')
        self.tarifadeaccesoatr = XmlField('TarifaDeAccesoATR')
        self.contratodeacceso = XmlField('ContratoDeAcceso')
        super(UtilitiesAtrAsociado, self).__init__('UtilitiesAtrAsociado', 'utilitiesatrasociado')

# 2.2


class UtilitiesCurva(XmlModel):

    _sort_order = ('utilitiescurva', 'CurvaDiaria')

    def __init__(self):
        self.utilitiescurva = XmlField('UtilitiesCurva')
        self.CurvaDiaria = []
        super(UtilitiesCurva, self).__init__('UtilitiesCurva', 'utilitiescurva')

# 2.2


class CurvaDiaria(XmlModel):

    _sort_order = ('curvadiaria', 'fechacurva', 'DatosCurva')

    def __init__(self):
        self.curvadiaria = XmlField('CurvaDiaria')
        self.fechacurva = XmlField('FechaCurva')
        self.DatosCurva = DatosCurva()
        super(CurvaDiaria, self).__init__('CurvaDiaria', 'curvadiaria')

# 2.2


class DatosCurva(XmlModel):

    _sort_order = ('datoscurva', 'tipologiacurva', 'tipovalor', 'periodicidad', 'valorcurva')

    def __init__(self):
        self.datoscurva = XmlField('DatosCurva')
        self.tipologiacurva = XmlField('TipologiaCurva')
        self.tipovalor = XmlField('TipoValor')
        self.periodicidad = XmlField('Periodicidad')
        self.valorcurva = XmlField('ValorCurva')
        super(DatosCurva, self).__init__('DatosCurva', 'datoscurva')

# 2.2















