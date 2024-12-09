#!/usr/bin/env python

#
# Generated Tue Dec  3 15:28:21 2024 by generateDS.py version 2.44.3.
# Python 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)]
#
# Command line options:
#   ('-o', 'trustedlists_api.py')
#   ('-s', 'trustedlists_sub.py')
#   ('--super', 'trustedlists_api')
#
# Command line arguments:
#   ts_119612v020101_xsd_modified.xsd
#
# Command line:
#   generateDS.py -o "trustedlists_api.py" -s "trustedlists_sub.py" --super="trustedlists_api" ts_119612v020101_xsd_modified.xsd
#
# Current working directory (os.getcwd()):
#   trusted_lists
#

import os
import sys
from lxml import etree as etree_

import trustedlists_api as supermod

def parsexml_(infile, parser=None, **kwargs):
    if parser is None:
        # Use the lxml ElementTree compatible parser so that, e.g.,
        #   we ignore comments.
        parser = etree_.ETCompatXMLParser()
    try:
        if isinstance(infile, os.PathLike):
            infile = os.path.join(infile)
    except AttributeError:
        pass
    doc = etree_.parse(infile, parser=parser, **kwargs)
    return doc

def parsexmlstring_(instring, parser=None, **kwargs):
    if parser is None:
        # Use the lxml ElementTree compatible parser so that, e.g.,
        #   we ignore comments.
        try:
            parser = etree_.ETCompatXMLParser()
        except AttributeError:
            # fallback to xml.etree
            parser = etree_.XMLParser()
    element = etree_.fromstring(instring, parser=parser, **kwargs)
    return element

#
# Globals
#

ExternalEncoding = ''
SaveElementTreeNode = True

#
# Data representation classes
#


class InternationalNamesTypeSub(supermod.InternationalNamesType):
    def __init__(self, Name=None, **kwargs_):
        super(InternationalNamesTypeSub, self).__init__(Name,  **kwargs_)
supermod.InternationalNamesType.subclass = InternationalNamesTypeSub
# end class InternationalNamesTypeSub


class MultiLangNormStringTypeSub(supermod.MultiLangNormStringType):
    def __init__(self, lang=None, valueOf_=None, **kwargs_):
        super(MultiLangNormStringTypeSub, self).__init__(lang, valueOf_,  **kwargs_)
supermod.MultiLangNormStringType.subclass = MultiLangNormStringTypeSub
# end class MultiLangNormStringTypeSub


class MultiLangStringTypeSub(supermod.MultiLangStringType):
    def __init__(self, lang=None, valueOf_=None, **kwargs_):
        super(MultiLangStringTypeSub, self).__init__(lang, valueOf_,  **kwargs_)
supermod.MultiLangStringType.subclass = MultiLangStringTypeSub
# end class MultiLangStringTypeSub


class AddressTypeSub(supermod.AddressType):
    def __init__(self, PostalAddresses=None, ElectronicAddress=None, **kwargs_):
        super(AddressTypeSub, self).__init__(PostalAddresses, ElectronicAddress,  **kwargs_)
supermod.AddressType.subclass = AddressTypeSub
# end class AddressTypeSub


class PostalAddressListTypeSub(supermod.PostalAddressListType):
    def __init__(self, PostalAddress=None, **kwargs_):
        super(PostalAddressListTypeSub, self).__init__(PostalAddress,  **kwargs_)
supermod.PostalAddressListType.subclass = PostalAddressListTypeSub
# end class PostalAddressListTypeSub


class PostalAddressTypeSub(supermod.PostalAddressType):
    def __init__(self, lang=None, StreetAddress=None, Locality=None, StateOrProvince=None, PostalCode=None, CountryName=None, **kwargs_):
        super(PostalAddressTypeSub, self).__init__(lang, StreetAddress, Locality, StateOrProvince, PostalCode, CountryName,  **kwargs_)
supermod.PostalAddressType.subclass = PostalAddressTypeSub
# end class PostalAddressTypeSub


class ElectronicAddressTypeSub(supermod.ElectronicAddressType):
    def __init__(self, URI=None, **kwargs_):
        super(ElectronicAddressTypeSub, self).__init__(URI,  **kwargs_)
supermod.ElectronicAddressType.subclass = ElectronicAddressTypeSub
# end class ElectronicAddressTypeSub


class AnyTypeSub(supermod.AnyType):
    def __init__(self, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, extensiontype_=None, **kwargs_):
        super(AnyTypeSub, self).__init__(anytypeobjs_, valueOf_, mixedclass_, content_, extensiontype_,  **kwargs_)
supermod.AnyType.subclass = AnyTypeSub
# end class AnyTypeSub


class ExtensionTypeSub(supermod.ExtensionType):
    def __init__(self, anytypeobjs_=None, Critical=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(ExtensionTypeSub, self).__init__(anytypeobjs_, Critical, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.ExtensionType.subclass = ExtensionTypeSub
# end class ExtensionTypeSub


class ExtensionsListTypeSub(supermod.ExtensionsListType):
    def __init__(self, Extension=None, **kwargs_):
        super(ExtensionsListTypeSub, self).__init__(Extension,  **kwargs_)
supermod.ExtensionsListType.subclass = ExtensionsListTypeSub
# end class ExtensionsListTypeSub


class NonEmptyMultiLangURIListTypeSub(supermod.NonEmptyMultiLangURIListType):
    def __init__(self, URI=None, **kwargs_):
        super(NonEmptyMultiLangURIListTypeSub, self).__init__(URI,  **kwargs_)
supermod.NonEmptyMultiLangURIListType.subclass = NonEmptyMultiLangURIListTypeSub
# end class NonEmptyMultiLangURIListTypeSub


class NonEmptyURIListTypeSub(supermod.NonEmptyURIListType):
    def __init__(self, URI=None, **kwargs_):
        super(NonEmptyURIListTypeSub, self).__init__(URI,  **kwargs_)
supermod.NonEmptyURIListType.subclass = NonEmptyURIListTypeSub
# end class NonEmptyURIListTypeSub


class TrustStatusListTypeSub(supermod.TrustStatusListType):
    def __init__(self, TSLTag=None, Id=None, SchemeInformation=None, TrustServiceProviderList=None, Signature=None, **kwargs_):
        super(TrustStatusListTypeSub, self).__init__(TSLTag, Id, SchemeInformation, TrustServiceProviderList, Signature,  **kwargs_)
supermod.TrustStatusListType.subclass = TrustStatusListTypeSub
# end class TrustStatusListTypeSub


class TrustServiceProviderListTypeSub(supermod.TrustServiceProviderListType):
    def __init__(self, TrustServiceProvider=None, **kwargs_):
        super(TrustServiceProviderListTypeSub, self).__init__(TrustServiceProvider,  **kwargs_)
supermod.TrustServiceProviderListType.subclass = TrustServiceProviderListTypeSub
# end class TrustServiceProviderListTypeSub


class TSLSchemeInformationTypeSub(supermod.TSLSchemeInformationType):
    def __init__(self, TSLVersionIdentifier=None, TSLSequenceNumber=None, TSLType=None, SchemeOperatorName=None, SchemeOperatorAddress=None, SchemeName=None, SchemeInformationURI=None, StatusDeterminationApproach=None, SchemeTypeCommunityRules=None, SchemeTerritory=None, PolicyOrLegalNotice=None, HistoricalInformationPeriod=None, PointersToOtherTSL=None, ListIssueDateTime=None, NextUpdate=None, DistributionPoints=None, SchemeExtensions=None, **kwargs_):
        super(TSLSchemeInformationTypeSub, self).__init__(TSLVersionIdentifier, TSLSequenceNumber, TSLType, SchemeOperatorName, SchemeOperatorAddress, SchemeName, SchemeInformationURI, StatusDeterminationApproach, SchemeTypeCommunityRules, SchemeTerritory, PolicyOrLegalNotice, HistoricalInformationPeriod, PointersToOtherTSL, ListIssueDateTime, NextUpdate, DistributionPoints, SchemeExtensions,  **kwargs_)
supermod.TSLSchemeInformationType.subclass = TSLSchemeInformationTypeSub
# end class TSLSchemeInformationTypeSub


class PolicyOrLegalnoticeTypeSub(supermod.PolicyOrLegalnoticeType):
    def __init__(self, TSLPolicy=None, TSLLegalNotice=None, **kwargs_):
        super(PolicyOrLegalnoticeTypeSub, self).__init__(TSLPolicy, TSLLegalNotice,  **kwargs_)
supermod.PolicyOrLegalnoticeType.subclass = PolicyOrLegalnoticeTypeSub
# end class PolicyOrLegalnoticeTypeSub


class NextUpdateTypeSub(supermod.NextUpdateType):
    def __init__(self, dateTime=None, **kwargs_):
        super(NextUpdateTypeSub, self).__init__(dateTime,  **kwargs_)
supermod.NextUpdateType.subclass = NextUpdateTypeSub
# end class NextUpdateTypeSub


class OtherTSLPointersTypeSub(supermod.OtherTSLPointersType):
    def __init__(self, OtherTSLPointer=None, **kwargs_):
        super(OtherTSLPointersTypeSub, self).__init__(OtherTSLPointer,  **kwargs_)
supermod.OtherTSLPointersType.subclass = OtherTSLPointersTypeSub
# end class OtherTSLPointersTypeSub


class OtherTSLPointerTypeSub(supermod.OtherTSLPointerType):
    def __init__(self, ServiceDigitalIdentities=None, TSLLocation=None, AdditionalInformation=None, **kwargs_):
        super(OtherTSLPointerTypeSub, self).__init__(ServiceDigitalIdentities, TSLLocation, AdditionalInformation,  **kwargs_)
supermod.OtherTSLPointerType.subclass = OtherTSLPointerTypeSub
# end class OtherTSLPointerTypeSub


class ServiceDigitalIdentityListTypeSub(supermod.ServiceDigitalIdentityListType):
    def __init__(self, ServiceDigitalIdentity=None, **kwargs_):
        super(ServiceDigitalIdentityListTypeSub, self).__init__(ServiceDigitalIdentity,  **kwargs_)
supermod.ServiceDigitalIdentityListType.subclass = ServiceDigitalIdentityListTypeSub
# end class ServiceDigitalIdentityListTypeSub


class AdditionalInformationTypeSub(supermod.AdditionalInformationType):
    def __init__(self, TextualInformation=None, OtherInformation=None, **kwargs_):
        super(AdditionalInformationTypeSub, self).__init__(TextualInformation, OtherInformation,  **kwargs_)
supermod.AdditionalInformationType.subclass = AdditionalInformationTypeSub
# end class AdditionalInformationTypeSub


class TSPTypeSub(supermod.TSPType):
    def __init__(self, TSPInformation=None, TSPServices=None, **kwargs_):
        super(TSPTypeSub, self).__init__(TSPInformation, TSPServices,  **kwargs_)
supermod.TSPType.subclass = TSPTypeSub
# end class TSPTypeSub


class TSPInformationTypeSub(supermod.TSPInformationType):
    def __init__(self, TSPName=None, TSPTradeName=None, TSPAddress=None, TSPInformationURI=None, TSPInformationExtensions=None, **kwargs_):
        super(TSPInformationTypeSub, self).__init__(TSPName, TSPTradeName, TSPAddress, TSPInformationURI, TSPInformationExtensions,  **kwargs_)
supermod.TSPInformationType.subclass = TSPInformationTypeSub
# end class TSPInformationTypeSub


class TSPServicesListTypeSub(supermod.TSPServicesListType):
    def __init__(self, TSPService=None, **kwargs_):
        super(TSPServicesListTypeSub, self).__init__(TSPService,  **kwargs_)
supermod.TSPServicesListType.subclass = TSPServicesListTypeSub
# end class TSPServicesListTypeSub


class TSPServiceTypeSub(supermod.TSPServiceType):
    def __init__(self, ServiceInformation=None, ServiceHistory=None, **kwargs_):
        super(TSPServiceTypeSub, self).__init__(ServiceInformation, ServiceHistory,  **kwargs_)
supermod.TSPServiceType.subclass = TSPServiceTypeSub
# end class TSPServiceTypeSub


class TSPServiceInformationTypeSub(supermod.TSPServiceInformationType):
    def __init__(self, ServiceTypeIdentifier=None, ServiceName=None, ServiceDigitalIdentity=None, ServiceStatus=None, StatusStartingTime=None, SchemeServiceDefinitionURI=None, ServiceSupplyPoints=None, TSPServiceDefinitionURI=None, ServiceInformationExtensions=None, **kwargs_):
        super(TSPServiceInformationTypeSub, self).__init__(ServiceTypeIdentifier, ServiceName, ServiceDigitalIdentity, ServiceStatus, StatusStartingTime, SchemeServiceDefinitionURI, ServiceSupplyPoints, TSPServiceDefinitionURI, ServiceInformationExtensions,  **kwargs_)
supermod.TSPServiceInformationType.subclass = TSPServiceInformationTypeSub
# end class TSPServiceInformationTypeSub


class ServiceSupplyPointsTypeSub(supermod.ServiceSupplyPointsType):
    def __init__(self, ServiceSupplyPoint=None, **kwargs_):
        super(ServiceSupplyPointsTypeSub, self).__init__(ServiceSupplyPoint,  **kwargs_)
supermod.ServiceSupplyPointsType.subclass = ServiceSupplyPointsTypeSub
# end class ServiceSupplyPointsTypeSub


class DigitalIdentityListTypeSub(supermod.DigitalIdentityListType):
    def __init__(self, DigitalId=None, **kwargs_):
        super(DigitalIdentityListTypeSub, self).__init__(DigitalId,  **kwargs_)
supermod.DigitalIdentityListType.subclass = DigitalIdentityListTypeSub
# end class DigitalIdentityListTypeSub


class DigitalIdentityTypeSub(supermod.DigitalIdentityType):
    def __init__(self, X509Certificate=None, X509SubjectName=None, KeyValue=None, X509SKI=None, Other=None, **kwargs_):
        super(DigitalIdentityTypeSub, self).__init__(X509Certificate, X509SubjectName, KeyValue, X509SKI, Other,  **kwargs_)
supermod.DigitalIdentityType.subclass = DigitalIdentityTypeSub
# end class DigitalIdentityTypeSub


class ServiceHistoryTypeSub(supermod.ServiceHistoryType):
    def __init__(self, ServiceHistoryInstance=None, **kwargs_):
        super(ServiceHistoryTypeSub, self).__init__(ServiceHistoryInstance,  **kwargs_)
supermod.ServiceHistoryType.subclass = ServiceHistoryTypeSub
# end class ServiceHistoryTypeSub


class ServiceHistoryInstanceTypeSub(supermod.ServiceHistoryInstanceType):
    def __init__(self, ServiceTypeIdentifier=None, ServiceName=None, ServiceDigitalIdentity=None, ServiceStatus=None, StatusStartingTime=None, ServiceInformationExtensions=None, **kwargs_):
        super(ServiceHistoryInstanceTypeSub, self).__init__(ServiceTypeIdentifier, ServiceName, ServiceDigitalIdentity, ServiceStatus, StatusStartingTime, ServiceInformationExtensions,  **kwargs_)
supermod.ServiceHistoryInstanceType.subclass = ServiceHistoryInstanceTypeSub
# end class ServiceHistoryInstanceTypeSub


class AdditionalServiceInformationTypeSub(supermod.AdditionalServiceInformationType):
    def __init__(self, URI=None, InformationValue=None, OtherInformation=None, **kwargs_):
        super(AdditionalServiceInformationTypeSub, self).__init__(URI, InformationValue, OtherInformation,  **kwargs_)
supermod.AdditionalServiceInformationType.subclass = AdditionalServiceInformationTypeSub
# end class AdditionalServiceInformationTypeSub


class QualificationsTypeSub(supermod.QualificationsType):
    def __init__(self, QualificationElement=None, **kwargs_):
        super(QualificationsTypeSub, self).__init__(QualificationElement,  **kwargs_)
supermod.QualificationsType.subclass = QualificationsTypeSub
# end class QualificationsTypeSub


class QualificationElementTypeSub(supermod.QualificationElementType):
    def __init__(self, Qualifiers=None, CriteriaList=None, **kwargs_):
        super(QualificationElementTypeSub, self).__init__(Qualifiers, CriteriaList,  **kwargs_)
supermod.QualificationElementType.subclass = QualificationElementTypeSub
# end class QualificationElementTypeSub


class CriteriaListTypeSub(supermod.CriteriaListType):
    def __init__(self, assert_=None, KeyUsage=None, PolicySet=None, CriteriaList=None, Description=None, otherCriteriaList=None, **kwargs_):
        super(CriteriaListTypeSub, self).__init__(assert_, KeyUsage, PolicySet, CriteriaList, Description, otherCriteriaList,  **kwargs_)
supermod.CriteriaListType.subclass = CriteriaListTypeSub
# end class CriteriaListTypeSub


class QualifiersTypeSub(supermod.QualifiersType):
    def __init__(self, Qualifier=None, **kwargs_):
        super(QualifiersTypeSub, self).__init__(Qualifier,  **kwargs_)
supermod.QualifiersType.subclass = QualifiersTypeSub
# end class QualifiersTypeSub


class QualifierTypeSub(supermod.QualifierType):
    def __init__(self, uri=None, **kwargs_):
        super(QualifierTypeSub, self).__init__(uri,  **kwargs_)
supermod.QualifierType.subclass = QualifierTypeSub
# end class QualifierTypeSub


class PoliciesListTypeSub(supermod.PoliciesListType):
    def __init__(self, PolicyIdentifier=None, **kwargs_):
        super(PoliciesListTypeSub, self).__init__(PolicyIdentifier,  **kwargs_)
supermod.PoliciesListType.subclass = PoliciesListTypeSub
# end class PoliciesListTypeSub


class ObjectIdentifierTypeSub(supermod.ObjectIdentifierType):
    def __init__(self, Identifier=None, **kwargs_):
        super(ObjectIdentifierTypeSub, self).__init__(Identifier,  **kwargs_)
supermod.ObjectIdentifierType.subclass = ObjectIdentifierTypeSub
# end class ObjectIdentifierTypeSub


class IdentifierTypeSub(supermod.IdentifierType):
    def __init__(self, anytypeobjs_=None, Qualifier=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(IdentifierTypeSub, self).__init__(anytypeobjs_, Qualifier, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.IdentifierType.subclass = IdentifierTypeSub
# end class IdentifierTypeSub


class DocumentationReferencesTypeSub(supermod.DocumentationReferencesType):
    def __init__(self, DocumentationReference=None, **kwargs_):
        super(DocumentationReferencesTypeSub, self).__init__(DocumentationReference,  **kwargs_)
supermod.DocumentationReferencesType.subclass = DocumentationReferencesTypeSub
# end class DocumentationReferencesTypeSub


class KeyUsageTypeSub(supermod.KeyUsageType):
    def __init__(self, KeyUsageBit=None, **kwargs_):
        super(KeyUsageTypeSub, self).__init__(KeyUsageBit,  **kwargs_)
supermod.KeyUsageType.subclass = KeyUsageTypeSub
# end class KeyUsageTypeSub


class KeyUsageBitTypeSub(supermod.KeyUsageBitType):
    def __init__(self, name=None, valueOf_=None, **kwargs_):
        super(KeyUsageBitTypeSub, self).__init__(name, valueOf_,  **kwargs_)
supermod.KeyUsageBitType.subclass = KeyUsageBitTypeSub
# end class KeyUsageBitTypeSub


class ExtendedKeyUsageTypeSub(supermod.ExtendedKeyUsageType):
    def __init__(self, KeyPurposeId=None, **kwargs_):
        super(ExtendedKeyUsageTypeSub, self).__init__(KeyPurposeId,  **kwargs_)
supermod.ExtendedKeyUsageType.subclass = ExtendedKeyUsageTypeSub
# end class ExtendedKeyUsageTypeSub


class TakenOverByTypeSub(supermod.TakenOverByType):
    def __init__(self, URI=None, TSPName=None, SchemeOperatorName=None, SchemeTerritory=None, OtherQualifier=None, **kwargs_):
        super(TakenOverByTypeSub, self).__init__(URI, TSPName, SchemeOperatorName, SchemeTerritory, OtherQualifier,  **kwargs_)
supermod.TakenOverByType.subclass = TakenOverByTypeSub
# end class TakenOverByTypeSub


class CertSubjectDNAttributeTypeSub(supermod.CertSubjectDNAttributeType):
    def __init__(self, AttributeOID=None, **kwargs_):
        super(CertSubjectDNAttributeTypeSub, self).__init__(AttributeOID,  **kwargs_)
supermod.CertSubjectDNAttributeType.subclass = CertSubjectDNAttributeTypeSub
# end class CertSubjectDNAttributeTypeSub


class SignatureTypeSub(supermod.SignatureType):
    def __init__(self, Id=None, SignedInfo=None, SignatureValue=None, KeyInfo=None, Object=None, **kwargs_):
        super(SignatureTypeSub, self).__init__(Id, SignedInfo, SignatureValue, KeyInfo, Object,  **kwargs_)
supermod.SignatureType.subclass = SignatureTypeSub
# end class SignatureTypeSub


class SignatureValueTypeSub(supermod.SignatureValueType):
    def __init__(self, Id=None, valueOf_=None, **kwargs_):
        super(SignatureValueTypeSub, self).__init__(Id, valueOf_,  **kwargs_)
supermod.SignatureValueType.subclass = SignatureValueTypeSub
# end class SignatureValueTypeSub


class SignedInfoTypeSub(supermod.SignedInfoType):
    def __init__(self, Id=None, CanonicalizationMethod=None, SignatureMethod=None, Reference=None, **kwargs_):
        super(SignedInfoTypeSub, self).__init__(Id, CanonicalizationMethod, SignatureMethod, Reference,  **kwargs_)
supermod.SignedInfoType.subclass = SignedInfoTypeSub
# end class SignedInfoTypeSub


class CanonicalizationMethodTypeSub(supermod.CanonicalizationMethodType):
    def __init__(self, Algorithm=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(CanonicalizationMethodTypeSub, self).__init__(Algorithm, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.CanonicalizationMethodType.subclass = CanonicalizationMethodTypeSub
# end class CanonicalizationMethodTypeSub


class SignatureMethodTypeSub(supermod.SignatureMethodType):
    def __init__(self, Algorithm=None, HMACOutputLength=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(SignatureMethodTypeSub, self).__init__(Algorithm, HMACOutputLength, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.SignatureMethodType.subclass = SignatureMethodTypeSub
# end class SignatureMethodTypeSub


class ReferenceTypeSub(supermod.ReferenceType):
    def __init__(self, Id=None, URI=None, Type=None, Transforms=None, DigestMethod=None, DigestValue=None, **kwargs_):
        super(ReferenceTypeSub, self).__init__(Id, URI, Type, Transforms, DigestMethod, DigestValue,  **kwargs_)
supermod.ReferenceType.subclass = ReferenceTypeSub
# end class ReferenceTypeSub


class TransformsTypeSub(supermod.TransformsType):
    def __init__(self, Transform=None, **kwargs_):
        super(TransformsTypeSub, self).__init__(Transform,  **kwargs_)
supermod.TransformsType.subclass = TransformsTypeSub
# end class TransformsTypeSub


class TransformTypeSub(supermod.TransformType):
    def __init__(self, Algorithm=None, anytypeobjs_=None, XPath=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(TransformTypeSub, self).__init__(Algorithm, anytypeobjs_, XPath, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.TransformType.subclass = TransformTypeSub
# end class TransformTypeSub


class DigestMethodTypeSub(supermod.DigestMethodType):
    def __init__(self, Algorithm=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(DigestMethodTypeSub, self).__init__(Algorithm, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.DigestMethodType.subclass = DigestMethodTypeSub
# end class DigestMethodTypeSub


class KeyInfoTypeSub(supermod.KeyInfoType):
    def __init__(self, Id=None, KeyName=None, KeyValue=None, RetrievalMethod=None, X509Data=None, PGPData=None, SPKIData=None, MgmtData=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(KeyInfoTypeSub, self).__init__(Id, KeyName, KeyValue, RetrievalMethod, X509Data, PGPData, SPKIData, MgmtData, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.KeyInfoType.subclass = KeyInfoTypeSub
# end class KeyInfoTypeSub


class KeyValueTypeSub(supermod.KeyValueType):
    def __init__(self, DSAKeyValue=None, RSAKeyValue=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(KeyValueTypeSub, self).__init__(DSAKeyValue, RSAKeyValue, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.KeyValueType.subclass = KeyValueTypeSub
# end class KeyValueTypeSub


class RetrievalMethodTypeSub(supermod.RetrievalMethodType):
    def __init__(self, URI=None, Type=None, Transforms=None, **kwargs_):
        super(RetrievalMethodTypeSub, self).__init__(URI, Type, Transforms,  **kwargs_)
supermod.RetrievalMethodType.subclass = RetrievalMethodTypeSub
# end class RetrievalMethodTypeSub


class X509DataTypeSub(supermod.X509DataType):
    def __init__(self, X509IssuerSerial=None, X509SKI=None, X509SubjectName=None, X509Certificate=None, X509CRL=None, anytypeobjs_=None, **kwargs_):
        super(X509DataTypeSub, self).__init__(X509IssuerSerial, X509SKI, X509SubjectName, X509Certificate, X509CRL, anytypeobjs_,  **kwargs_)
supermod.X509DataType.subclass = X509DataTypeSub
# end class X509DataTypeSub


class X509IssuerSerialTypeSub(supermod.X509IssuerSerialType):
    def __init__(self, X509IssuerName=None, X509SerialNumber=None, **kwargs_):
        super(X509IssuerSerialTypeSub, self).__init__(X509IssuerName, X509SerialNumber,  **kwargs_)
supermod.X509IssuerSerialType.subclass = X509IssuerSerialTypeSub
# end class X509IssuerSerialTypeSub


class PGPDataTypeSub(supermod.PGPDataType):
    def __init__(self, PGPKeyID=None, PGPKeyPacket=None, anytypeobjs_=None, **kwargs_):
        super(PGPDataTypeSub, self).__init__(PGPKeyID, PGPKeyPacket, anytypeobjs_,  **kwargs_)
supermod.PGPDataType.subclass = PGPDataTypeSub
# end class PGPDataTypeSub


class SPKIDataTypeSub(supermod.SPKIDataType):
    def __init__(self, SPKISexp=None, anytypeobjs_=None, **kwargs_):
        super(SPKIDataTypeSub, self).__init__(SPKISexp, anytypeobjs_,  **kwargs_)
supermod.SPKIDataType.subclass = SPKIDataTypeSub
# end class SPKIDataTypeSub


class ObjectTypeSub(supermod.ObjectType):
    def __init__(self, Id=None, MimeType=None, Encoding=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(ObjectTypeSub, self).__init__(Id, MimeType, Encoding, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.ObjectType.subclass = ObjectTypeSub
# end class ObjectTypeSub


class ManifestTypeSub(supermod.ManifestType):
    def __init__(self, Id=None, Reference=None, **kwargs_):
        super(ManifestTypeSub, self).__init__(Id, Reference,  **kwargs_)
supermod.ManifestType.subclass = ManifestTypeSub
# end class ManifestTypeSub


class SignaturePropertiesTypeSub(supermod.SignaturePropertiesType):
    def __init__(self, Id=None, SignatureProperty=None, **kwargs_):
        super(SignaturePropertiesTypeSub, self).__init__(Id, SignatureProperty,  **kwargs_)
supermod.SignaturePropertiesType.subclass = SignaturePropertiesTypeSub
# end class SignaturePropertiesTypeSub


class SignaturePropertyTypeSub(supermod.SignaturePropertyType):
    def __init__(self, Target=None, Id=None, anytypeobjs_=None, valueOf_=None, mixedclass_=None, content_=None, **kwargs_):
        super(SignaturePropertyTypeSub, self).__init__(Target, Id, anytypeobjs_, valueOf_, mixedclass_, content_,  **kwargs_)
supermod.SignaturePropertyType.subclass = SignaturePropertyTypeSub
# end class SignaturePropertyTypeSub


class DSAKeyValueTypeSub(supermod.DSAKeyValueType):
    def __init__(self, P=None, Q=None, G=None, Y=None, J=None, Seed=None, PgenCounter=None, **kwargs_):
        super(DSAKeyValueTypeSub, self).__init__(P, Q, G, Y, J, Seed, PgenCounter,  **kwargs_)
supermod.DSAKeyValueType.subclass = DSAKeyValueTypeSub
# end class DSAKeyValueTypeSub


class RSAKeyValueTypeSub(supermod.RSAKeyValueType):
    def __init__(self, Modulus=None, Exponent=None, **kwargs_):
        super(RSAKeyValueTypeSub, self).__init__(Modulus, Exponent,  **kwargs_)
supermod.RSAKeyValueType.subclass = RSAKeyValueTypeSub
# end class RSAKeyValueTypeSub


class NonEmptyURITypeSub(supermod.NonEmptyURIType):
    def __init__(self, valueOf_=None, extensiontype_=None, **kwargs_):
        super(NonEmptyURITypeSub, self).__init__(valueOf_, extensiontype_,  **kwargs_)
supermod.NonEmptyURIType.subclass = NonEmptyURITypeSub
# end class NonEmptyURITypeSub


class DigestValueTypeSub(supermod.DigestValueType):
    def __init__(self, valueOf_=None, **kwargs_):
        super(DigestValueTypeSub, self).__init__(valueOf_,  **kwargs_)
supermod.DigestValueType.subclass = DigestValueTypeSub
# end class DigestValueTypeSub


class NonEmptyMultiLangURITypeSub(supermod.NonEmptyMultiLangURIType):
    def __init__(self, lang=None, valueOf_=None, **kwargs_):
        super(NonEmptyMultiLangURITypeSub, self).__init__(lang, valueOf_,  **kwargs_)
supermod.NonEmptyMultiLangURIType.subclass = NonEmptyMultiLangURITypeSub
# end class NonEmptyMultiLangURITypeSub


def get_root_tag(node):
    tag = supermod.Tag_pattern_.match(node.tag).groups()[-1]
    rootClass = None
    rootClass = supermod.GDSClassesMapping.get(tag)
    if rootClass is None and hasattr(supermod, tag):
        rootClass = getattr(supermod, tag)
    return tag, rootClass


def parse(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'InternationalNamesType'
        rootClass = supermod.InternationalNamesType
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    if not SaveElementTreeNode:
        doc = None
        rootNode = None
    if not silence:
        sys.stdout.write('<?xml version="1.0" ?>\n')
        rootObj.export(
            sys.stdout, 0, name_=rootTag,
            namespacedef_='xmlns:tsl="http://uri.etsi.org/02231/v2#"',
            pretty_print=True)
    return rootObj


def parseEtree(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'InternationalNamesType'
        rootClass = supermod.InternationalNamesType
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    mapping = {}
    rootElement = rootObj.to_etree(None, name_=rootTag, mapping_=mapping)
    reverse_mapping = rootObj.gds_reverse_node_mapping(mapping)
    # Enable Python to collect the space used by the DOM.
    if not SaveElementTreeNode:
        doc = None
        rootNode = None
    if not silence:
        content = etree_.tostring(
            rootElement, pretty_print=True,
            xml_declaration=True, encoding="utf-8")
        sys.stdout.write(content)
        sys.stdout.write('\n')
    return rootObj, rootElement, mapping, reverse_mapping


def parseString(inString, silence=False):
    if sys.version_info.major == 2:
        from StringIO import StringIO
    else:
        from io import BytesIO as StringIO
    parser = None
    rootNode= parsexmlstring_(inString, parser)
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'InternationalNamesType'
        rootClass = supermod.InternationalNamesType
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    if not SaveElementTreeNode:
        rootNode = None
    if not silence:
        sys.stdout.write('<?xml version="1.0" ?>\n')
        rootObj.export(
            sys.stdout, 0, name_=rootTag,
            namespacedef_='xmlns:tsl="http://uri.etsi.org/02231/v2#"')
    return rootObj


def parseLiteral(inFilename, silence=False):
    parser = None
    doc = parsexml_(inFilename, parser)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'InternationalNamesType'
        rootClass = supermod.InternationalNamesType
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    if not SaveElementTreeNode:
        doc = None
        rootNode = None
    if not silence:
        sys.stdout.write('#from trustedlists_api import *\n\n')
        sys.stdout.write('import trustedlists_api as model_\n\n')
        sys.stdout.write('rootObj = model_.rootClass(\n')
        rootObj.exportLiteral(sys.stdout, 0, name_=rootTag)
        sys.stdout.write(')\n')
    return rootObj


USAGE_TEXT = """
Usage: python ???.py <infilename>
"""


def usage():
    print(USAGE_TEXT)
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if len(args) != 1:
        usage()
    infilename = args[0]
    parse(infilename)


if __name__ == '__main__':
    #import pdb; pdb.set_trace()
    main()
