# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import base64
import datetime
from io import StringIO
import io
import xml.etree.ElementTree as xml
from dateutil.relativedelta import relativedelta
from flask import send_file
from signxml import DigestAlgorithm
from signxml.xades import (XAdESSigner, XAdESSignaturePolicy, XAdESDataObjectFormat)
import xml_gen.trustedlists_api as test
from signxml import DigestAlgorithm
from signxml.xades import (XAdESSigner, XAdESSignaturePolicy, XAdESDataObjectFormat)
from xml_gen.xml_config import ConfXML as confxml
from signxml import XMLSigner, algorithms
import json

from app_config.config import ConfService as cfgserv
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
from lxml import etree
import xml.etree.ElementTree as ET

def parse_json_field(field):
    try:
        return json.loads(field) if isinstance(field, str) else field
    except json.JSONDecodeError:
        return field
    
def xml_gen_xml(user_info, dictFromDB_trusted_lists, tsp_data, service_data):
    service_data = [service for sublist in service_data for service in sublist]
    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()

    schemeInfo.TSLVersionIdentifier=confxml.TLSVersionIdentifier
    schemeInfo.TSLSequenceNumber=dictFromDB_trusted_lists["SequenceNumber"] + 1
    TSLType=test.NonEmptyURIType()
    TSLType.set_valueOf_(dictFromDB_trusted_lists["TSLType"])
    schemeInfo.TSLType=TSLType

    #schemeOperatorName

    schemeOName = test.InternationalNamesType()

    #for cycle
    op_name = parse_json_field(user_info["operator_name"])
    for item in op_name:
        schemeOName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

    schemeInfo.SchemeOperatorName=schemeOName

    #Scheme Operator Address
    schemeOAddress= test.AddressType()

    eletronic=test.ElectronicAddressType()

    #for cycle
    EletronicAddress = parse_json_field(user_info["EletronicAddress"])
    for item in EletronicAddress:
        eletronic.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))
    #----------------------------------------------------#
    schemeOAddress.set_ElectronicAddress(eletronic)

    PostalAdresses=test.PostalAddressListType()

    #for cycle for postal address
    postal = parse_json_field(user_info["postal_address"])
    for item in postal:
        postal=test.PostalAddressType()
        postal.set_lang(item['lang'])
        postal.set_CountryName(item["CountryName"])
        postal.set_StreetAddress(item["StreetAddress"])
        postal.set_Locality(item["Locality"])
        postal.set_StateOrProvince(item["StateOrProvince"])
        postal.set_PostalCode(item["PostalCode"])
        PostalAdresses.add_PostalAddress(postal)

    schemeOAddress.set_PostalAddresses(PostalAdresses)
    schemeInfo.SchemeOperatorAddress=schemeOAddress

    #schemeName
    schemeName=test.InternationalNamesType()

    #for cycle
    schemeName.add_Name(test.MultiLangNormStringType("en",dictFromDB_trusted_lists["SchemeName"]))

    schemeInfo.set_SchemeName(schemeName)

    #SchemeInformationURI
    schemeInformationURI=test.NonEmptyMultiLangURIListType()

    #for cycle
    schemeInformationURI.add_URI(test.NonEmptyMultiLangURIType("en",dictFromDB_trusted_lists["SchemeInformationURI"]))

    schemeInfo.set_SchemeInformationURI(schemeInformationURI)

    #StatusDeterminationApproach
    schemeInfo.StatusDeterminationApproach=test.NonEmptyURIType(dictFromDB_trusted_lists["StatusDeterminationApproach"])
    
    #schemeTypeCommunityRules
    schemeCRules= test.NonEmptyMultiLangURIListType()

    #for cycle
    schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", dictFromDB_trusted_lists["SchemeTypeCommunityRules"]))
    
    schemeInfo.set_SchemeTypeCommunityRules(schemeCRules)

    #SchemeTerritory
    schemeInfo.set_SchemeTerritory(user_info["country"])

    #PolicyOrLegalNotice
    PolicyOrLegalNotice= test.PolicyOrLegalnoticeType()

    #for cycle
    PolicyOrLegalNotice.add_TSLLegalNotice(test.MultiLangStringType("en", dictFromDB_trusted_lists["PolicyOrLegalNotice"]))
    
    schemeInfo.set_PolicyOrLegalNotice(PolicyOrLegalNotice)

    #HistoricalInformationPeriod
    schemeInfo.set_HistoricalInformationPeriod(dictFromDB_trusted_lists["HistoricalInformationPeriod"])

    #PointerToOtherTSL
    Pointers= test.OtherTSLPointersType()

    Pointer= test.OtherTSLPointerType()

    ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()

    #for cycle
    ServiceDigitalIdentities.add_ServiceDigitalIdentity(test.DigitalIdentityType(dictFromDB_trusted_lists["pointers_to_other_tsl"]))
    
    Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

    #additional Info
    AdditionalInfo=test.AdditionalInformationType()
    
    #for cycle
    AdditionalInfo.add_OtherInformation(test.AnyType("TSLType: ", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"))

    schemeNametest=test.InternationalNamesType()

    #for cycle
    schemeNametest.add_Name(test.MultiLangNormStringType("en",dictFromDB_trusted_lists["SchemeName"]))

    AdditionalInfo.add_OtherInformation(schemeNametest)
    
    Pointer.TSLLocation=test.NonEmptyURIType("https://trustedlist.eudiw.dev/tools/lotl/eu-lotl.xml")
    
    Pointer.AdditionalInformation=AdditionalInfo

    Pointers.add_OtherTSLPointer(Pointer)
    schemeInfo.PointersToOtherTSL=Pointers
    
    schemeInfo.set_ListIssueDateTime=dictFromDB_trusted_lists["issue_date"]
    
    #Next Update
    NUpdate=test.NextUpdateType()
    NUpdate.set_dateTime(dictFromDB_trusted_lists["next_update"])
    schemeInfo.NextUpdate= NUpdate

    #DistribuitionPoints
    URIDP=test.NonEmptyURIListType()

    #for cycle
    URIDP.add_URI(test.NonEmptyURIType(dictFromDB_trusted_lists["DistributionPoints"]))

    schemeInfo.DistributionPoints=URIDP

    root.SchemeInformation=schemeInfo

    #--------------------------------------------#

    #TrustServiceProviderList

    TrustServiceProviderList=test.TrustServiceProviderListType()
    TrustServiceProvider= test.TSPType()
    TSPInformation=test.TSPInformationType()
    TSPName=test.InternationalNamesType()
    TSPTradeName= test.InternationalNamesType()
    TSPAddress=test.AddressType()
    TSPPostalAddress=test.PostalAddressListType()
    TSPEletronicAddress=test.ElectronicAddressType()
    TSPInformationURI= test.NonEmptyMultiLangURIListType()

    for each in tsp_data:
        name = parse_json_field(each["name"])
        for item in name:
            TSPName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

        trade_name = parse_json_field(each["trade_name"])
        for item in trade_name:
            TSPTradeName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

        address = parse_json_field(each["postal_address"])
        for item in address:
            postal1=test.PostalAddressType()
            postal1.set_lang(item['lang'])
            postal1.set_CountryName(item["CountryName"])
            postal1.set_StreetAddress(item["StreetAddress"])
            postal1.set_Locality(item["Locality"])
            postal1.set_StateOrProvince(item["StateOrProvince"])
            postal1.set_PostalCode(item["PostalCode"])
            TSPPostalAddress.add_PostalAddress(postal1)
        
        
    
        ele_address = parse_json_field(each["EletronicAddress"])
        for item in ele_address:
            TSPEletronicAddress.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))


        uri = parse_json_field(each["TSPInformationURI"])
        for item in uri:
            TSPInformationURI.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))

        TSPAddress.set_PostalAddresses(TSPPostalAddress)
        TSPAddress.set_ElectronicAddress(TSPEletronicAddress)
        TSPInformation.set_TSPName(TSPName)
        TSPInformation.set_TSPTradeName(TSPTradeName)
        TSPInformation.set_TSPAddress(TSPAddress)
        TSPInformation.set_TSPInformationURI(TSPInformationURI)
        TrustServiceProvider.set_TSPInformation(TSPInformation)

    #Services
    TSPServices=test.TSPServicesListType()

    #for cycle
    TSPService=test.TSPServiceType()
    ServiceInformation=test.TSPServiceInformationType()
    ServiceName=test.InternationalNamesType()
    ServiceDigitalIdentity=test.ServiceDigitalIdentityListType()
    SchemeServiceDefinitionURI=test.NonEmptyMultiLangURIListType()
    ServiceInformationExtensions=test.ExtensionsListType()
    Extension =test.ExtensionType()
    Qualifications=test.QualificationsType()
    qualificationElement=test.QualificationElementType()
    qualifiers=test.QualifiersType()
    qualifier=test.QualifierType()
    CriteriaList=test.CriteriaListType()
    PolicySet=test.PoliciesListType()
    PolicyIdentifier=test.ObjectIdentifierType()
    Identifier=test.IdentifierType()
    AdditionalServiceInformation=test.AdditionalServiceInformationType()
    ExtensionAdditionalServiceInformation=test.ExtensionType()
    ExtensionAdditionalServiceInformation.set_anytypeobjs_(test.AdditionalServiceInformationType())
    Extension.set_anytypeobjs_(test.QualificationsType())

    for each in service_data:
        ServiceInformation.set_ServiceTypeIdentifier(test.NonEmptyURIType(each["service_type"]))

        serv_name = parse_json_field(each["ServiceName"])
        for item in serv_name:
            ServiceName.add_Name(test.MultiLangNormStringType(item["lang"], item["text"]))
            ServiceInformation.set_ServiceName(ServiceName)

        ServiceDigitalIdentity.add_ServiceDigitalIdentity(test.DigitalIdentityType(each["digital_identity"]))
        ServiceInformation.set_ServiceDigitalIdentity(ServiceDigitalIdentities)

        ServiceInformation.set_ServiceStatus(test.NonEmptyURIType(each["status"]))
        ServiceInformation.set_StatusStartingTime(datetime.datetime.now())

        uri = parse_json_field(each["SchemeServiceDefinitionURI"])
        for item in uri:
            SchemeServiceDefinitionURI.add_URI(test.NonEmptyMultiLangURIType(item["lang"],item["URI"]))
            ServiceInformation.set_SchemeServiceDefinitionURI(SchemeServiceDefinitionURI)

        #Extensions

        #Qualification
        Qualifications.__setattr__("_Critical",True)

        qualifier.set_uri(each["qualifier"])
        qualifiers.add_Qualifier(qualifier)

        Identifier.set_Qualifier("OIDAsURI")
        Identifier.set_valueOf_("0.4.0.194112.1.2")
        PolicyIdentifier.add_Identifier(Identifier)
    

    PolicySet.add_PolicyIdentifier(PolicyIdentifier)

    CriteriaList.add_PolicySet(PolicySet)
    CriteriaList.set_assert("all")

    qualificationElement.set_CriteriaList(CriteriaList)
    qualificationElement.set_Qualifiers(qualifiers)

    Qualifications.add_QualificationElement(qualificationElement)

    
    AdditionalServiceInformation.set_URI(test.NonEmptyMultiLangURIType("en","	https://www.teste.com"))
    Extension.set_valueOf_(Qualifications)
    Extension.set_Critical(True)

    ExtensionAdditionalServiceInformation.set_valueOf_(AdditionalServiceInformation)
    ExtensionAdditionalServiceInformation.set_Critical(True)

    ServiceInformationExtensions.add_Extension(Extension)
    ServiceInformationExtensions.add_Extension(ExtensionAdditionalServiceInformation)
    ServiceInformation.set_ServiceInformationExtensions(ServiceInformationExtensions)

        #AdditionalServiceInformation		
    

    ##ServiceHistoryInstance
    #equal to Service Information
    ServiceHistory=test.ServiceHistoryType()
    ServiceHistoryInstance=test.ServiceHistoryInstanceType()

    ServiceHistory.add_ServiceHistoryInstance(ServiceHistoryInstance)

    TSPService.set_ServiceInformation(ServiceInformation)
    TSPService.set_ServiceHistory(ServiceHistory)
    TSPServices.add_TSPService(TSPService)
    TrustServiceProvider.set_TSPServices(TSPServices)
    TrustServiceProviderList.add_TrustServiceProvider(TrustServiceProvider)

    root.set_TrustServiceProviderList(TrustServiceProviderList)

    xml_buffer=StringIO()
    root.export(xml_buffer,0,"")
    xml_string=xml_buffer.getvalue()

    # with open ("cert_UT.pem", "rb") as file: 
    #     cert = file.read()
    #     cert=x509.load_pem_x509_certificate(cert)
    
    der_data=open(cfgserv.cert_UT, "rb").read()
    cert = x509.load_der_x509_certificate(der_data)
    cert = cert.public_bytes(encoding=serialization.Encoding.PEM)

    cert_for_hash=x509.load_pem_x509_certificate(cert, default_backend())
    thumbprint= hashlib.sha256(cert_for_hash.tbs_certificate_bytes).hexdigest()

    # with open ("privkey_UT.pem", "rb") as key_file: 
    #     key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
        
    key=open(cfgserv.priv_key_UT, "rb").read()
    xml.register_namespace("","http://uri.etsi.org/02231/v2#")
    
    rootTemp=xml.fromstring(xml_string)

    root_temp_str = ET.tostring(rootTemp, encoding="utf-8")
    root_lxml = etree.fromstring(root_temp_str)
    root_bytes = etree.tostring(root_lxml, method="c14n")
    xml_hash_before_sign = hashlib.sha256(root_bytes).hexdigest()

    signed_root = XMLSigner(signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256).sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
    
    xml_data = io.BytesIO()
    tree.write(xml_data, encoding='utf-8', xml_declaration=True)
    xml_data.seek(0)

    encoded_file = base64.b64encode(xml_data.read()).decode('utf-8')


    return encoded_file, thumbprint, xml_hash_before_sign


def xml_gen_lotl_xml(user_info, tsl_list, dict_tsl_mom):
    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()
    TSLType=test.NonEmptyURIType()

    schemeInfo.TSLVersionIdentifier=confxml.TLSVersionIdentifier
    schemeInfo.TSLSequenceNumber=dict_tsl_mom["SequenceNumber"] + 1
    
    TSLType.set_valueOf_(confxml.TSLType["EUDIW"])
    schemeInfo.TSLType=TSLType

    #schemeOperatorName

    schemeOName = test.InternationalNamesType()

    #for cycle
    op_name = parse_json_field(user_info["operator_name"])
    for item in op_name:
        schemeOName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

    schemeInfo.SchemeOperatorName=schemeOName

    #Scheme Operator Address
    schemeOAddress= test.AddressType()

    eletronic=test.ElectronicAddressType()

    #for cycle
    EletronicAddress = parse_json_field(user_info["EletronicAddress"])
    for item in EletronicAddress:
        eletronic.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))
    #----------------------------------------------------#
    schemeOAddress.set_ElectronicAddress(eletronic)

    PostalAdresses=test.PostalAddressListType()

    #for cycle for postal address
    postal = parse_json_field(user_info["postal_address"])
    for item in postal:
        postal=test.PostalAddressType()
        postal.set_lang(item['lang'])
        postal.set_CountryName(item["CountryName"])
        postal.set_StreetAddress(item["StreetAddress"])
        postal.set_Locality(item["Locality"])
        postal.set_StateOrProvince(item["StateOrProvince"])
        postal.set_PostalCode(item["PostalCode"])
        PostalAdresses.add_PostalAddress(postal)

    schemeOAddress.set_PostalAddresses(PostalAdresses)
    schemeInfo.SchemeOperatorAddress=schemeOAddress
    
    schemeName=test.InternationalNamesType()
    PolicyOrLegalNotice= test.PolicyOrLegalnoticeType()
    schemeInformationURI=test.NonEmptyMultiLangURIListType()
    schemeCRules= test.NonEmptyMultiLangURIListType()
    Pointers=test.OtherTSLPointersType()
    

    #schemeName
    #for cycle
    schemeName.add_Name(test.MultiLangNormStringType("en",dict_tsl_mom["SchemeName"]))

    schemeInfo.set_SchemeName(schemeName)

    #SchemeInformationURI
    
    #for cycle
    schemeInformationURI.add_URI(test.NonEmptyMultiLangURIType("en",dict_tsl_mom["SchemeInformationURI"]))

    schemeInfo.set_SchemeInformationURI(schemeInformationURI)

    #StatusDeterminationApproach
    schemeInfo.StatusDeterminationApproach=test.NonEmptyURIType(confxml.StatusDeterminationApproach["EUDIW"])
    
    #schemeTypeCommunityRules

#for cycle
    schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["EUDIW"]))

    schemeInfo.set_SchemeTypeCommunityRules(schemeCRules)

    #SchemeTerritory
    schemeInfo.set_SchemeTerritory(user_info["country"])

    #PolicyOrLegalNotice

    #for cycle
    PolicyOrLegalNotice.add_TSLLegalNotice(test.MultiLangStringType("en", dict_tsl_mom["PolicyOrLegalNotice"]))

    schemeInfo.set_PolicyOrLegalNotice(PolicyOrLegalNotice)

    #HistoricalInformationPeriod
    schemeInfo.set_HistoricalInformationPeriod(dict_tsl_mom["HistoricalInformationPeriod"])

    #PointerToOtherTSL

    #for cycle
    for tsl_data in tsl_list:
        ServiceDigitalIdentities= test.ServiceDigitalIdentityListType() 
        ServiceDigitalIdentities.add_ServiceDigitalIdentity(test.DigitalIdentityType(tsl_data["pointers_to_other_tsl"]))
        Pointer= test.OtherTSLPointerType()
        Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

        #additional Info
        
        #TSLTypeAdditionalInformation
        TSLTypeAdditionalInformation=test.NonEmptyURIType()
        TSLTypeAdditionalInformation.original_tagname_="TSLType"
        TSLTypeAdditionalInformation.valueOf_=(tsl_data["TSLType"])

        objecttest=test.AnyType()
        objecttest.valueOf_=TSLTypeAdditionalInformation
        
        AdditionalInfo=test.AdditionalInformationType()
        AdditionalInfo.add_OtherInformation(objecttest)

        #SchemeNameOperatorAdditionalInformation
        #for cycle
        schemeNametest=test.InternationalNamesType()
        schemeNametest.add_Name(test.MultiLangNormStringType("en", tsl_data["SchemeName"]))

        testes=test.TakenOverByType()
        testes.SchemeOperatorName=schemeNametest

        AdditionalInfo.add_OtherInformation(testes)

        #SchemeTerritoryAdditionalInformatio

        scheme=test.TakenOverByType()
        scheme.SchemeTerritory="PT"

        AdditionalInfo.add_OtherInformation(scheme)


        #SchemeTypeCommunityRules
        
        schemetypeCommunityRules_add=test.NonEmptyMultiLangURIListType()
        schemetypeCommunityRules_add.original_tagname_="SchemeTypeCommunityRules"
        
        objecttest_stcr=test.AnyType()
        objecttest_stcr.original_tagname_="SchemeTypeCommunityRules"

        #for cycle
        schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", tsl_data["SchemeTypeCommunityRules"]))

        objecttest_stcr.valueOf_=schemetypeCommunityRules_add

        AdditionalInfo.add_OtherInformation(objecttest_stcr)

        #MimeType
        ObjectType=test.ObjectType()
        ObjectType.original_tagname_="MimeType"
        ObjectType.set__prefix("ns3")
        ObjectType.set_valueOf_("application/vnd.etsi.tsl+xml")

        objectMimeType=test.AnyType()
        objectMimeType.set_valueOf_(ObjectType)

        AdditionalInfo.add_OtherInformation(objectMimeType)

        Pointer.TSLLocation=test.NonEmptyURIType("https://trustedlist.eudiw.dev/tools/lotl/eu-lotl.xml")

        Pointer.AdditionalInformation=AdditionalInfo
        Pointers.add_OtherTSLPointer(Pointer)
    
    schemeInfo.PointersToOtherTSL=Pointers
    
    schemeInfo.set_ListIssueDateTime=dict_tsl_mom["issue_date"]
    
    #Next Update
    NUpdate=test.NextUpdateType()
    NUpdate.set_dateTime(dict_tsl_mom["next_update"])
    schemeInfo.NextUpdate= NUpdate

    #DistribuitionPoints

    #for cycle
    URIDP=test.NonEmptyURIListType()
    
    URIDP.add_URI(test.NonEmptyURIType(confxml.DistributionPoints["EUDIW"]))

    schemeInfo.DistributionPoints=URIDP

    root.SchemeInformation=schemeInfo

    xml_buffer=StringIO()
    root.export(xml_buffer,0,"")
    xml_string=xml_buffer.getvalue()

    # with open ("cert_UT.pem", "rb") as file: 
    #     cert = file.read()
    #     cert=x509.load_pem_x509_certificate(cert)
    
    der_data=open(cfgserv.cert_UT, "rb").read()
    cert = x509.load_der_x509_certificate(der_data)
    cert = cert.public_bytes(encoding=serialization.Encoding.PEM)

    cert_for_hash=x509.load_pem_x509_certificate(cert, default_backend())
    thumbprint= hashlib.sha256(cert_for_hash.tbs_certificate_bytes).hexdigest()

    # with open ("privkey_UT.pem", "rb") as key_file: 
    #     key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
        
    key=open(cfgserv.priv_key_UT, "rb").read()
    xml.register_namespace("","http://uri.etsi.org/02231/v2#")
    
    rootTemp=xml.fromstring(xml_string)

    root_temp_str = ET.tostring(rootTemp, encoding="utf-8")
    root_lxml = etree.fromstring(root_temp_str)
    root_bytes = etree.tostring(root_lxml, method="c14n")
    xml_hash_before_sign = hashlib.sha256(root_bytes).hexdigest()

    signed_root = XMLSigner(signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256).sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
    
    xml_data = io.BytesIO()
    tree.write(xml_data, encoding='utf-8', xml_declaration=True)
    xml_data.seek(0)

    encoded_file = base64.b64encode(xml_data.read()).decode('utf-8')


    return encoded_file, thumbprint, xml_hash_before_sign
