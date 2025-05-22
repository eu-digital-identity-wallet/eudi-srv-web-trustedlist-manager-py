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
from signxml.xades import (XAdESSigner, XAdESSignaturePolicy, XAdESDataObjectFormat)
from xml_gen.xml_config import ConfXML as confxml
from signxml import XMLSigner, algorithms, methods
import json

from app_config.config import ConfService as cfgserv
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
from lxml import etree
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.serialization import Encoding
import app.EJBCA_and_DB_func as func

def parse_json_field(field):
    try:
        return json.loads(field) if isinstance(field, str) else field
    except json.JSONDecodeError:
        return field
    
def xml_gen_xml(user_info, dictFromDB_trusted_lists, tsp_data, service_data, tsl_id, log_id):
    service_data = [service for sublist in service_data for service in sublist]

    der_data=open(cfgserv.cert_UT, "rb").read()
    cert_der = x509.load_der_x509_certificate(der_data)
    cert = cert_der.public_bytes(encoding=serialization.Encoding.PEM)

    pem_str = cert.decode('utf-8')
    cert_cleaned = ''.join(line for line in pem_str.splitlines() if "CERTIFICATE" not in line)

    check = func.get_old_cert(tsl_id, log_id)
    aux = 0
    if(check is not None):
        for each in check:
            if(each["cert"] != cert_cleaned):
                aux = 1
    else:
        if(aux != 1):
            func.insert_old_cert(cert_cleaned, tsl_id, log_id)
    
    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()

    schemeInfo.TSLVersionIdentifier=confxml.TLSVersionIdentifier
    schemeInfo.TSLSequenceNumber=dictFromDB_trusted_lists["SequenceNumber"] + 1
    TSLType=test.NonEmptyURIType()
    TSLType.set_valueOf_(confxml.TSLType["EU"])
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
    for scheme in dictFromDB_trusted_lists["SchemeName"]:
        schemeName.add_Name(test.MultiLangNormStringType(scheme["lang"], scheme["text"]))
    
    schemeInfo.set_SchemeName(schemeName)

    #SchemeInformationURI
    schemeInformationURI=test.NonEmptyMultiLangURIListType()

    #for cycle
    for scheme in dictFromDB_trusted_lists["SchemeInformationURI"]:
        schemeInformationURI.add_URI(test.NonEmptyMultiLangURIType(scheme["lang"], scheme["URI"]))
    
    schemeInfo.set_SchemeInformationURI(schemeInformationURI)

    #StatusDeterminationApproach
    schemeInfo.StatusDeterminationApproach=test.NonEmptyURIType(confxml.StatusDeterminationApproach["EU"])
    
    #schemeTypeCommunityRules
    schemeCRules= test.NonEmptyMultiLangURIListType()

    #for cycle
    schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["EU"]))
    schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["Country"] + dictFromDB_trusted_lists["schemeTerritory"] ))
    schemeInfo.set_SchemeTypeCommunityRules(schemeCRules)

    #SchemeTerritory
    schemeInfo.set_SchemeTerritory(dictFromDB_trusted_lists["schemeTerritory"])

    #PolicyOrLegalNotice
    PolicyOrLegalNotice= test.PolicyOrLegalnoticeType()

    #for cycle
    for scheme in dictFromDB_trusted_lists["PolicyOrLegalNotice"]:
        PolicyOrLegalNotice.add_TSLLegalNotice(test.MultiLangStringType(scheme["lang"], scheme["text"]))
        schemeInfo.set_PolicyOrLegalNotice(PolicyOrLegalNotice)

    #HistoricalInformationPeriod
    schemeInfo.set_HistoricalInformationPeriod(dictFromDB_trusted_lists["HistoricalInformationPeriod"])

    #PointerToOtherTSL
    Pointers= test.OtherTSLPointersType()

    #OtherTSLPointerType-LoTL

    ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()
    serviceDigitalIdentity=test.DigitalIdentityListType()

    digitalID=test.DigitalIdentityType()
    digitalID.set_X509Certificate(base64.b64decode(cert_cleaned))

    serviceDigitalIdentity.add_DigitalId(digitalID)
    ServiceDigitalIdentities.add_ServiceDigitalIdentity(serviceDigitalIdentity)

    Pointer= test.OtherTSLPointerType()
    Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

    #additional Info
    
    #TSLTypeAdditionalInformation

    TSLTypeAdditionalInformation=test.NonEmptyURIType()
    TSLTypeAdditionalInformation.original_tagname_="TSLType"
    TSLTypeAdditionalInformation.valueOf_=confxml.TSLType["LoTL"]

    objecttest=test.AnyType()
    objecttest.valueOf_=TSLTypeAdditionalInformation
    
    AdditionalInfo=test.AdditionalInformationType()
    AdditionalInfo.add_OtherInformation(objecttest)

    #SchemeNameOperatorAdditionalInformation
    #for cycle
    schemeNametest=test.InternationalNamesType()
    schemeNametest.add_Name(test.MultiLangNormStringType("en", "EU-LOTL"))

    testes=test.TakenOverByType()
    testes.SchemeOperatorName=schemeNametest

    AdditionalInfo.add_OtherInformation(testes)

    #SchemeTerritoryAdditionalInformation

    scheme=test.TakenOverByType()
    scheme.SchemeTerritory="EU"

    AdditionalInfo.add_OtherInformation(scheme)


    #SchemeTypeCommunityRules
    
    schemetypeCommunityRules_add=test.NonEmptyMultiLangURIListType()
    schemetypeCommunityRules_add.original_tagname_="SchemeTypeCommunityRules"
    
    objecttest_stcr=test.AnyType()
    objecttest_stcr.original_tagname_="SchemeTypeCommunityRules"

    #for cycle
    schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["LoTL"]))

    objecttest_stcr.valueOf_=schemetypeCommunityRules_add

    AdditionalInfo.add_OtherInformation(objecttest_stcr)

    #MimeType
    ObjectType=test.ObjectType()
    ObjectType.original_tagname_="MimeType"
    ObjectType.set_valueOf_("application/vnd.etsi.tsl+xml")

    objectMimeType=test.AnyType()
    objectMimeType.set_valueOf_(ObjectType)

    AdditionalInfo.add_OtherInformation(objectMimeType)

    Pointer.TSLLocation=test.NonEmptyURIType(confxml.lotl_location)

    Pointer.AdditionalInformation=AdditionalInfo
    Pointers.add_OtherTSLPointer(Pointer)

    schemeInfo.PointersToOtherTSL=Pointers
    
    schemeInfo.ListIssueDateTime=dictFromDB_trusted_lists["issue_date"]
    
    #Next Update
    NUpdate=test.NextUpdateType()
    NUpdate.set_dateTime(dictFromDB_trusted_lists["next_update"])
    
    schemeInfo.NextUpdate= NUpdate

    #DistribuitionPoints
    URIDP=test.NonEmptyURIListType()

    #for cycle
    
    # for dp in dictFromDB_trusted_lists["DistributionPoints"]:
    #     URIDP.add_URI(test.NonEmptyURIType(dp))
    last= dictFromDB_trusted_lists["SchemeInformationURI"][-1].get("URI")

    URIDP.add_URI(test.NonEmptyURIType(last))

    schemeInfo.DistributionPoints=URIDP

    root.SchemeInformation=schemeInfo

    #--------------------------------------------#

    #TrustServiceProviderList

    TrustServiceProviderList=test.TrustServiceProviderListType()


    for tsp in tsp_data:
        TrustServiceProvider= test.TSPType()
        TSPInformation=test.TSPInformationType()
        TSPName=test.InternationalNamesType()
        TSPTradeName= test.InternationalNamesType()
        TSPAddress=test.AddressType()
        TSPPostalAddress=test.PostalAddressListType()
        TSPEletronicAddress=test.ElectronicAddressType()
        TSPInformationURI= test.NonEmptyMultiLangURIListType()

        name = parse_json_field(tsp["name"])
        for item in name:
            TSPName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

        trade_name = parse_json_field(tsp["trade_name"])
        for item in trade_name:
            TSPTradeName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

        address = parse_json_field(tsp["postal_address"])
        for item in address:
            postal1=test.PostalAddressType()
            postal1.set_lang(item['lang'])
            postal1.set_CountryName(item["CountryName"])
            postal1.set_StreetAddress(item["StreetAddress"])
            postal1.set_Locality(item["Locality"])
            postal1.set_StateOrProvince(item["StateOrProvince"])
            postal1.set_PostalCode(item["PostalCode"])
            TSPPostalAddress.add_PostalAddress(postal1)
        
        
    
        ele_address = parse_json_field(tsp["EletronicAddress"])
        for item in ele_address:
            TSPEletronicAddress.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))


        uri = parse_json_field(tsp["TSPInformationURI"])
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

        #ServiceInformationExtensions=test.ExtensionsListType()
        # Extension =test.ExtensionType()
        # Qualifications=test.QualificationsType()
        # qualificationElement=test.QualificationElementType()
        # qualifiers=test.QualifiersType()
        # qualifier=test.QualifierType()
        # CriteriaList=test.CriteriaListType()
        # PolicySet=test.PoliciesListType()
        # PolicyIdentifier=test.ObjectIdentifierType()
        # Identifier=test.IdentifierType()
        # AdditionalServiceInformation=test.AdditionalServiceInformationType()
        # ExtensionAdditionalServiceInformation=test.ExtensionType()
        # ExtensionAdditionalServiceInformation.set_anytypeobjs_(test.AdditionalServiceInformationType())
        # Extension.set_anytypeobjs_(test.QualificationsType())

        for each in service_data:

            if each["tsp_id"] == tsp["tsp_id"]:
                
                TSPService=test.TSPServiceType()
                ServiceInformation=test.TSPServiceInformationType()
                ServiceName=test.InternationalNamesType()
                SchemeServiceDefinitionURI=test.NonEmptyMultiLangURIListType()

                ServiceInformation.set_ServiceTypeIdentifier(test.NonEmptyURIType(each["service_type"]))

                serv_name = parse_json_field(each["ServiceName"])
                for item in serv_name:
                    ServiceName.add_Name(test.MultiLangNormStringType(item["lang"], item["text"]))

                ServiceInformation.set_ServiceName(ServiceName)

                ServiceDigitalIdentity=test.DigitalIdentityListType()
                digitalID = test.DigitalIdentityType()
                digitalID.set_X509Certificate(base64.b64decode(each["digital_identity"]))
                ServiceDigitalIdentity.add_DigitalId(digitalID)
                ServiceInformation.set_ServiceDigitalIdentity(ServiceDigitalIdentity)

                ServiceInformation.set_ServiceStatus(test.NonEmptyURIType(each["status"]))
                ServiceInformation.set_StatusStartingTime(each["status_start_date"])

                uri = parse_json_field(each["SchemeServiceDefinitionURI"])
                for item in uri:
                    SchemeServiceDefinitionURI.add_URI(test.NonEmptyMultiLangURIType(item["lang"],item["URI"]))
                
                ServiceInformation.set_SchemeServiceDefinitionURI(SchemeServiceDefinitionURI)

                #Extensions

                #Qualification
                # Qualifications.__setattr__("_Critical",True)

                # qualifier.set_uri(each["qualifier"])
                # qualifiers.add_Qualifier(qualifier)

                # Identifier.set_Qualifier("OIDAsURI")
                # Identifier.set_valueOf_("0.4.0.194112.1.2")
                # PolicyIdentifier.add_Identifier(Identifier)
            

                # PolicySet.add_PolicyIdentifier(PolicyIdentifier)

                # CriteriaList.add_PolicySet(PolicySet)
                # CriteriaList.set_assert("all")

                # qualificationElement.set_CriteriaList(CriteriaList)
                # qualificationElement.set_Qualifiers(qualifiers)

                # Qualifications.add_QualificationElement(qualificationElement)

                
                # AdditionalServiceInformation.set_URI(test.NonEmptyMultiLangURIType("en","	https://www.teste.com"))
                # Extension.set_valueOf_(Qualifications)
                # Extension.set_Critical(True)

                # ExtensionAdditionalServiceInformation.set_valueOf_(AdditionalServiceInformation)
                # ExtensionAdditionalServiceInformation.set_Critical(True)

                # ServiceInformationExtensions.add_Extension(Extension)
                # ServiceInformationExtensions.add_Extension(ExtensionAdditionalServiceInformation)
                # ServiceInformation.set_ServiceInformationExtensions(ServiceInformationExtensions)

                TSPService.set_ServiceInformation(ServiceInformation)
                TSPServices.add_TSPService(TSPService)

        #AdditionalServiceInformation		
        TrustServiceProvider.set_TSPServices(TSPServices)
        TrustServiceProviderList.add_TrustServiceProvider(TrustServiceProvider)

    root.set_TrustServiceProviderList(TrustServiceProviderList)

    xml_buffer=StringIO()
    root.export(xml_buffer,0,"")
    xml_string=xml_buffer.getvalue()

    # with open ("cert_UT.pem", "rb") as file: 
    #     cert = file.read()
    #     cert=x509.load_pem_x509_certificate(cert)

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

    data_object_format = XAdESDataObjectFormat(
        Description="TSL signature",
        MimeType="text/xml",
    )
    signer = XAdESSigner(
        claimed_roles=["signer"],
        data_object_format=data_object_format,
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256,
        method=methods.enveloped
    )

    signed_root = signer.sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
    
    xml_data = io.BytesIO()
    tree.write(xml_data, encoding='utf-8', xml_declaration=True)
    xml_data.seek(0)

    encoded_file = base64.b64encode(xml_data.read()).decode('utf-8')


    return encoded_file, thumbprint, xml_hash_before_sign


def xml_gen_lotl_xml(user_info, tsl_list, dict_tsl_mom, log_id):

    der_data=open(cfgserv.cert_UT, "rb").read()
    cert_der= x509.load_der_x509_certificate(der_data)
    cert = cert_der.public_bytes(encoding=serialization.Encoding.PEM)

    pem_str = cert.decode('utf-8')
    cert_cleaned = ''.join(line for line in pem_str.splitlines() if "CERTIFICATE" not in line)

    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()
    TSLType=test.NonEmptyURIType()

    schemeInfo.TSLVersionIdentifier=confxml.TLSVersionIdentifier
    schemeInfo.TSLSequenceNumber=dict_tsl_mom["SequenceNumber"] + 1
    
    TSLType.set_valueOf_(confxml.TSLType["LoTL"])
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
    for scheme in dict_tsl_mom["SchemeName"]:
        schemeName.add_Name(test.MultiLangNormStringType(scheme["lang"], scheme["text"]))
    
    schemeInfo.set_SchemeName(schemeName)

    #SchemeInformationURI
    
    #for cycle
    for scheme in dict_tsl_mom["SchemeInformationURI"]:
        schemeInformationURI.add_URI(test.NonEmptyMultiLangURIType(scheme["lang"], scheme["URI"]))
    
    schemeInfo.set_SchemeInformationURI(schemeInformationURI)

    #StatusDeterminationApproach
    schemeInfo.StatusDeterminationApproach=test.NonEmptyURIType(confxml.StatusDeterminationApproach["LoTL"])
    
    #schemeTypeCommunityRules

#for cycle
    schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["LoTL"]))
    schemeInfo.set_SchemeTypeCommunityRules(schemeCRules)

    #SchemeTerritory
    schemeInfo.set_SchemeTerritory("EU")

    #PolicyOrLegalNotice

    #for cycle
    for scheme in dict_tsl_mom["PolicyOrLegalNotice"]:
        PolicyOrLegalNotice.add_TSLLegalNotice(test.MultiLangStringType(scheme["lang"], scheme["text"]))
    
    schemeInfo.set_PolicyOrLegalNotice(PolicyOrLegalNotice)

    #HistoricalInformationPeriod
    schemeInfo.set_HistoricalInformationPeriod(dict_tsl_mom["HistoricalInformationPeriod"])

    #PointerToOtherTSL

    #OtherTSLPointerType-LoTL

    ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()
    serviceDigitalIdentity=test.DigitalIdentityListType()

    digitalID=test.DigitalIdentityType()
    digitalID.set_X509Certificate(base64.b64decode(cert_cleaned))

    serviceDigitalIdentity.add_DigitalId(digitalID)
    ServiceDigitalIdentities.add_ServiceDigitalIdentity(serviceDigitalIdentity)
    Pointer= test.OtherTSLPointerType()
    Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

    #additional Info
    
    #TSLTypeAdditionalInformation

    TSLTypeAdditionalInformation=test.NonEmptyURIType()
    TSLTypeAdditionalInformation.original_tagname_="TSLType"
    TSLTypeAdditionalInformation.valueOf_=confxml.TSLType["LoTL"]

    objecttest=test.AnyType()
    objecttest.valueOf_=TSLTypeAdditionalInformation
    
    AdditionalInfo=test.AdditionalInformationType()
    AdditionalInfo.add_OtherInformation(objecttest)

    #SchemeNameOperatorAdditionalInformation
    #for cycle
    schemeNametest=test.InternationalNamesType()
    for item in op_name:
        schemeNametest.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))
    
    testes=test.TakenOverByType()
    testes.SchemeOperatorName=schemeNametest

    AdditionalInfo.add_OtherInformation(testes)

    #SchemeTerritoryAdditionalInformation

    scheme=test.TakenOverByType()
    scheme.SchemeTerritory="EU"

    AdditionalInfo.add_OtherInformation(scheme)


    #SchemeTypeCommunityRules
    
    schemetypeCommunityRules_add=test.NonEmptyMultiLangURIListType()
    schemetypeCommunityRules_add.original_tagname_="SchemeTypeCommunityRules"
    
    objecttest_stcr=test.AnyType()
    objecttest_stcr.original_tagname_="SchemeTypeCommunityRules"

    #for cycle
    schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["LoTL"]))

    objecttest_stcr.valueOf_=schemetypeCommunityRules_add

    AdditionalInfo.add_OtherInformation(objecttest_stcr)

    #MimeType
    ObjectType=test.ObjectType()
    ObjectType.original_tagname_="MimeType"
    ObjectType.set_valueOf_("application/vnd.etsi.tsl+xml")

    objectMimeType=test.AnyType()
    objectMimeType.set_valueOf_(ObjectType)

    AdditionalInfo.add_OtherInformation(objectMimeType)

    last = dict_tsl_mom["SchemeInformationURI"][-1].get("URI")
    Pointer.TSLLocation=test.NonEmptyURIType(last)

    Pointer.AdditionalInformation=AdditionalInfo
    Pointers.add_OtherTSLPointer(Pointer)

    #for cycle
    for tsl_data in tsl_list:
        ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()
        serviceDigitalIdentity=test.DigitalIdentityListType()

        #for cycle novo
        aux = func.get_old_cert(tsl_data["id"], log_id)

        for each in aux:
            digitalID=test.DigitalIdentityType()
            digitalID.set_X509Certificate(base64.b64decode(each["cert"]))
            serviceDigitalIdentity.add_DigitalId(digitalID)
        #end

        ServiceDigitalIdentities.add_ServiceDigitalIdentity(serviceDigitalIdentity)
        Pointer= test.OtherTSLPointerType()
        Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

        #additional Info
        
        #TSLTypeAdditionalInformation
        TSLTypeAdditionalInformation=test.NonEmptyURIType()
        TSLTypeAdditionalInformation.original_tagname_="TSLType"
        TSLTypeAdditionalInformation.valueOf_=(confxml.TSLType["EU"])

        objecttest=test.AnyType()
        objecttest.valueOf_=TSLTypeAdditionalInformation
        
        AdditionalInfo=test.AdditionalInformationType()
        AdditionalInfo.add_OtherInformation(objecttest)

        #SchemeNameOperatorAdditionalInformation
        #for cycle
        schemeNametest=test.InternationalNamesType()
        for item in tsl_data["SchemeName"]:
            schemeNametest.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

        testes=test.TakenOverByType()
        testes.SchemeOperatorName=schemeNametest

        AdditionalInfo.add_OtherInformation(testes)

        #SchemeTerritoryAdditionalInformatio

        scheme=test.TakenOverByType()
        scheme.SchemeTerritory=tsl_data["schemeTerritory"]

        AdditionalInfo.add_OtherInformation(scheme)


        #SchemeTypeCommunityRules
        
        schemetypeCommunityRules_add=test.NonEmptyMultiLangURIListType()
        schemetypeCommunityRules_add.original_tagname_="SchemeTypeCommunityRules"
        
        objecttest_stcr=test.AnyType()
        objecttest_stcr.original_tagname_="SchemeTypeCommunityRules"

        #for cycle
        schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["EU"]))
        schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", confxml.SchemeTypeCommunityRules["Country"] + tsl_data["schemeTerritory"]))
        objecttest_stcr.valueOf_=schemetypeCommunityRules_add

        AdditionalInfo.add_OtherInformation(objecttest_stcr)

        #MimeType
        ObjectType=test.ObjectType()
        ObjectType.original_tagname_="MimeType"
        ObjectType.set_valueOf_("application/vnd.etsi.tsl+xml")

        objectMimeType=test.AnyType()
        objectMimeType.set_valueOf_(ObjectType)

        AdditionalInfo.add_OtherInformation(objectMimeType)

        last= tsl_data["SchemeInformationURI"][-1].get("URI")
        Pointer.TSLLocation=test.NonEmptyURIType(last)

        Pointer.AdditionalInformation=AdditionalInfo
        Pointers.add_OtherTSLPointer(Pointer)
    
    schemeInfo.PointersToOtherTSL=Pointers
    
    schemeInfo.ListIssueDateTime=dict_tsl_mom["issue_date"]
    #Next Update
    NUpdate=test.NextUpdateType()
    NUpdate.set_dateTime(dict_tsl_mom["next_update"])
    schemeInfo.NextUpdate= NUpdate

    #DistribuitionPoints

    #for cycle
    URIDP=test.NonEmptyURIListType()
    last= dict_tsl_mom["SchemeInformationURI"][-1].get("URI")
    URIDP.add_URI(test.NonEmptyURIType(last))

    schemeInfo.DistributionPoints=URIDP

    root.SchemeInformation=schemeInfo

    xml_buffer=StringIO()
    root.export(xml_buffer,0,"")
    xml_string=xml_buffer.getvalue()

    # with open ("cert_UT.pem", "rb") as file: 
    #     cert = file.read()
    #     cert=x509.load_pem_x509_certificate(cert)

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

    data_object_format = XAdESDataObjectFormat(
        Description="TSL signature",
        MimeType="text/xml",
    )
    signer = XAdESSigner(
        claimed_roles=["signer"],
        data_object_format=data_object_format,
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256,
        method=methods.enveloped
    )

    signed_root = signer.sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
    
    xml_data = io.BytesIO()
    tree.write(xml_data, encoding='utf-8', xml_declaration=True)
    xml_data.seek(0)

    encoded_file = base64.b64encode(xml_data.read()).decode('utf-8')


    return encoded_file, thumbprint, xml_hash_before_sign


def xml_validator(file):

    # Load Schema
    with open(confxml.schema, 'rb') as f:
        schema_root = etree.parse(f)
        schema = etree.XMLSchema(schema_root)

    # Load XML
    # with open("teste2.xml", 'rb') as f:
    #     xml_tree = etree.parse(f)

    xml_tree= etree.fromstring(file)

    # Validate XML
    if schema.validate(xml_tree):
        return 200,"Valid XML"
    else:
        msg= "Invalid XML"
        for error in schema.error_log:
            msg = msg + f"\nLine {error.line}: {error.message}"
        
        return 500, msg

    