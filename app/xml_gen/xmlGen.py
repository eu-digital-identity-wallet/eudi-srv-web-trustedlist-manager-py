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

def parse_json_field(field):
    try:
        return json.loads(field) if isinstance(field, str) else field
    except json.JSONDecodeError:
        return field
    
def xml_gen(user_info, dictFromDB_trusted_lists, tsp_data, service_data, qualif):
    
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
    Pointers= test.OtherTSLPointerType()

    ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()

    #for cycle
    ServiceDigitalIdentities.add_ServiceDigitalIdentity(test.DigitalIdentityType(dictFromDB_trusted_lists["pointers_to_other_tsl"]))
    
    Pointers.ServiceDigitalIdentities=ServiceDigitalIdentities

    #additional Info
    AdditionalInfo=test.AdditionalInformationType()
    
    #for cycle
    AdditionalInfo.add_OtherInformation(test.AnyType("TSLType: ", test.NonEmptyURIType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists")))
    
    Pointers.TSLLocation=test.NonEmptyURIType("https://ec.europa.eu/tools/lotl/eu-lotl.xml")
    
    Pointers.AdditionalInformation=AdditionalInfo
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

    name = parse_json_field(tsp_data["name"])

    for item in name:
        TrustServiceProvider= test.TSPType()
        TSPInformation=test.TSPInformationType()
        TSPName=test.InternationalNamesType()
        TSPName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

    trade_name = parse_json_field(tsp_data["trade_name"])
    for item in trade_name:
        TSPTradeName= test.InternationalNamesType()
        TSPTradeName.add_Name(test.MultiLangNormStringType(item['lang'], item["text"]))

    address = parse_json_field(tsp_data["postal_address"])
    for item in address:
        TSPAddress=test.AddressType()

        TSPPostalAddress=test.PostalAddressListType()
        postal1=test.PostalAddressType()
        postal1.set_CountryName(item["CountryName"])
        postal1.set_StreetAddress(item["StreetAddress"])
        postal1.set_Locality(item["Locality"])
        postal1.set_StateOrProvince(item["StateOrProvince"])
        postal1.set_PostalCode(item["PostalCode"])
        TSPPostalAddress.add_PostalAddress(postal1)
    
    ele_address = parse_json_field(tsp_data["EletronicAddress"])
    for item in ele_address:
        TSPEletronicAddress=test.ElectronicAddressType()
        TSPEletronicAddress.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))

        TSPAddress.set_ElectronicAddress(TSPEletronicAddress)
        TSPAddress.set_PostalAddresses(TSPPostalAddress)

    uri = parse_json_field(tsp_data["TSPInformationURI"])
    for item in uri:
        TSPInformationURI= test.NonEmptyMultiLangURIListType()
        TSPInformationURI.add_URI(test.NonEmptyMultiLangURIType(item['lang'],item["URI"]))

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
    ServiceInformation.set_ServiceTypeIdentifier(test.NonEmptyURIType(service_data["service_type"]))

    serv_name = parse_json_field(service_data["ServiceName"])
    for item in serv_name:
        ServiceName=test.InternationalNamesType()
        ServiceName.add_Name(test.MultiLangNormStringType(item["lang"], item["text"]))
        ServiceInformation.set_ServiceName(ServiceName)

    ServiceDigitalIdentity=test.ServiceDigitalIdentityListType()
    ServiceDigitalIdentity.add_ServiceDigitalIdentity(test.DigitalIdentityType(service_data["digital_identity"]))
    ServiceInformation.set_ServiceDigitalIdentity(ServiceDigitalIdentities)

    ServiceInformation.set_ServiceStatus(test.NonEmptyURIType(service_data["status"]))
    ServiceInformation.set_StatusStartingTime(datetime.datetime.now())

    uri = parse_json_field(service_data["SchemeServiceDefinitionURI"])
    for item in uri:
        SchemeServiceDefinitionURI=test.NonEmptyMultiLangURIListType()
        SchemeServiceDefinitionURI.add_URI(test.NonEmptyMultiLangURIType(item["lang"],item["URI"]))
        ServiceInformation.set_SchemeServiceDefinitionURI(SchemeServiceDefinitionURI)

    #Extensions
    ServiceInformationExtensions=test.ExtensionsListType()

    #for cycle
    Extension =test.ExtensionType()

    #Qualification
    Qualifications=test.QualificationsType()
    Qualifications.__setattr__("_Critical",True)

    #for cycle
    qualificationElement=test.QualificationElementType()
    qualifiers=test.QualifiersType()

    #for cycle
    qualifier=test.QualifierType()
    qualifier.set_uri(qualif)
    qualifiers.add_Qualifier(qualifier)

    #for cycle
    CriteriaList=test.CriteriaListType()

    PolicySet=test.PoliciesListType()

    #for cycle
    PolicyIdentifier=test.ObjectIdentifierType()
    Identifier=test.IdentifierType()
    Identifier.set_Qualifier("OIDAsURI")
    Identifier.set_valueOf_("0.4.0.194112.1.2")
    PolicyIdentifier.add_Identifier(Identifier)

    PolicySet.add_PolicyIdentifier(PolicyIdentifier)

    CriteriaList.add_PolicySet(PolicySet)
    CriteriaList.set_assert("all")

    qualificationElement.set_CriteriaList(CriteriaList)
    qualificationElement.set_Qualifiers(qualifiers)

    Qualifications.add_QualificationElement(qualificationElement)


    #AdditionalServiceInformation		
    AdditionalServiceInformation=test.AdditionalServiceInformationType()
    AdditionalServiceInformation.set_URI(test.NonEmptyMultiLangURIType("en","	https://www.teste.com"))
    
    Extension.set_anytypeobjs_(test.QualificationsType())
    Extension.set_valueOf_(Qualifications)
    Extension.set_Critical(True)

    ExtensionAdditionalServiceInformation=test.ExtensionType()
    ExtensionAdditionalServiceInformation.set_anytypeobjs_(test.AdditionalServiceInformationType())
    ExtensionAdditionalServiceInformation.set_valueOf_(AdditionalServiceInformation)
    ExtensionAdditionalServiceInformation.set_Critical(True)

    ServiceInformationExtensions.add_Extension(Extension)
    ServiceInformationExtensions.add_Extension(ExtensionAdditionalServiceInformation)
    ServiceInformation.set_ServiceInformationExtensions(ServiceInformationExtensions)

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
    #     Cert=x509.load_pem_x509_certificate(cert)

    cert=open("app/xml_gen/cert_UT.pem", "rb").read()

    # with open ("privkey_UT.pem", "rb") as key_file: 
    #     key = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
        
    key=open("app/xml_gen/privkey_UT.pem", "rb").read()
    xml.register_namespace("","http://uri.etsi.org/02231/v2#")
    
    rootTemp=xml.fromstring(xml_string)

    signed_root = XMLSigner(signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256).sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
    
    xml_data = io.BytesIO()
    tree.write(xml_data, encoding='utf-8', xml_declaration=True)
    xml_data.seek(0)

    encoded_file = base64.b64encode(xml_data.read()).decode('utf-8')


    return encoded_file

    # with open ("xmlTest.xml", "wb") as files : 
    #     tree.write(files)


# if __name__ == "__main__":  
    # PostalAddress={
    #     "StreetAddress"	:	"Rua da Junqueira, 69",
    #     "Locality"	:	"Lisbon",
    #     "StateOrProvince"	:	"Lisbon",
    #     "PostalCode"	:	"1300-342 Lisboa",
    #     "CountryName"	:	"PT",
    #     "lang"	:	"en"
    # }

    # dictFromDB_scheme_operator={
    #     "operator_name":"test",
    #     "StreetAddress"	:	"Rua da Junqueira, 69",
    #     "Locality"	:	"Lisbon",
    #     "StateOrProvince"	:	"Lisbon",
    #     "PostalCode"	:	"1300-342 Lisboa",
    #     "CountryName"	:	"PT",
    #     "EletronicAddress":"teste@teste.pt",
    #     "country":"PT"
    # }

    # issue_date=datetime.datetime.now(datetime.timezone.utc)
    # next_update= issue_date + relativedelta(months=confxml.validity)

    # dictFromDB_trusted_lists={
    #     "Version":confxml.TLSIdentifier,
    #     "SequenceNumber":1,
    #     "TSLType":confxml.TSLType.get("EU"),
    #     "SchemeName":"text",
    #     "SchemeInformationURI":"link",
    #     "StatusDeterminationApproach":confxml.StatusDeterminationApproach.get("EU"),
    #     "SchemeTypeCommunityRules":"http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon",
    #     "PolicyOrLegalNotice":"texto",
    #     "pointers_to_other_tsl" :b"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",
    #     "HistoricalInformationPeriod":confxml.HistoricalInformationPeriod,
    #     "TSLLocation"	:	"https://ec.europa.eu/tools/lotl/eu-lotl.xml",
    #     #AdditionalInformation,ver

    #     "DistributionPoints" :"link",
    #     "issue_date" :issue_date,
    #     "next_update":next_update,
    #     "status":"http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
    # }


    # dictFromDB_trust_services={
    #     "service_type":"http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    #     "service_name":"text",
    #     "digital_identity" :b"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",
    #     "status" :"	http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
    #     "status_start_date":datetime.datetime.now(datetime.timezone.utc),
    #     "SchemeServiceDefinitionURI":"link",
    #     #"general":"JSON",
    #     # "qualifier" varchar(255) DEFAULT NULL,
    #     # "qualificationElement" varchar(255) DEFAULT NULL,
    #     # "criteriaList" varchar(255) DEFAULT NULL,
    #     # "takenOverBy" varchar(255) DEFAULT NULL,
    # }

    # dictFromDB_trust_service_providers={
    #     "name" :"text",
    #     "trade_name" :"text",
    #     "StreetAddress"	:	"Rua da Junqueira, 69",
    #     "Locality"	:	"Lisbon",
    #     "StateOrProvince"	:	"Lisbon",
    #     "PostalCode"	:	"1300-342 Lisboa",
    #     "CountryName"	:	"PT",
    #     "EletronicAddress":"teste@teste.pt",
    #     "TSPInformationURI":"link",
    #     "country":"PT"
    # }

    #xml_gen(PostalAddress, dictFromDB_scheme_operator, dictFromDB_trusted_lists, dictFromDB_trust_services, dictFromDB_trust_service_providers) 