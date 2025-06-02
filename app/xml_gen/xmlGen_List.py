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
    
def xml_gen_xml_lotl(user_info, tsl_list):
    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()
    TSLType=test.NonEmptyURIType()

    for tsl_data in tsl_list: 
        schemeInfo.TSLVersionIdentifier=confxml.TLSVersionIdentifier
        schemeInfo.TSLSequenceNumber=tsl_data["SequenceNumber"] + 1
        
        TSLType.set_valueOf_(tsl_data["TSLType"])
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
    Pointer= test.OtherTSLPointerType()
    ServiceDigitalIdentities= test.ServiceDigitalIdentityListType()
    AdditionalInfo=test.AdditionalInformationType()
    objecttest=test.AnyType()
    TSLTypeAdditionalInformation=test.NonEmptyURIType()
    schemeNametest=test.InternationalNamesType()
    testes=test.TakenOverByType()
    testes=test.TakenOverByType()
    schemetypeCommunityRules_add=test.NonEmptyMultiLangURIListType()
    objecttest=test.AnyType()
    ObjectType=test.ObjectType()
    ObjectType.original_tagname_="MimeType"
    objectMimeType=test.AnyType()
    NUpdate=test.NextUpdateType()
    URIDP=test.NonEmptyURIListType()


    for tsl_data in tsl_list: 
    #schemeName
    #for cycle
        schemeName.add_Name(test.MultiLangNormStringType("en",tsl_data["SchemeName"]))

        schemeInfo.set_SchemeName(schemeName)

    #SchemeInformationURI
    
    for tsl_data in tsl_list: 
    #for cycle
        schemeInformationURI.add_URI(test.NonEmptyMultiLangURIType("en",tsl_data["SchemeInformationURI"]))

        schemeInfo.set_SchemeInformationURI(schemeInformationURI)

    #StatusDeterminationApproach
    for tsl_data in tsl_list: 
        schemeInfo.StatusDeterminationApproach=test.NonEmptyURIType(tsl_data["StatusDeterminationApproach"])
    
    #schemeTypeCommunityRules

    for tsl_data in tsl_list: 
    #for cycle
        schemeCRules.add_URI(test.NonEmptyMultiLangURIType("en", tsl_data["SchemeTypeCommunityRules"]))
    
        schemeInfo.set_SchemeTypeCommunityRules(schemeCRules)

    #SchemeTerritory
    schemeInfo.set_SchemeTerritory(user_info["country"])

    #PolicyOrLegalNotice

    #for cycle
    for tsl_data in tsl_list: 
        PolicyOrLegalNotice.add_TSLLegalNotice(test.MultiLangStringType("en", tsl_data["PolicyOrLegalNotice"]))
    
        schemeInfo.set_PolicyOrLegalNotice(PolicyOrLegalNotice)

    #HistoricalInformationPeriod
    for tsl_data in tsl_list: 
        schemeInfo.set_HistoricalInformationPeriod(tsl_data["HistoricalInformationPeriod"])

    #PointerToOtherTSL

    #for cycle
    for tsl_data in tsl_list: 
        ServiceDigitalIdentities.add_ServiceDigitalIdentity(test.DigitalIdentityType(tsl_data["pointers_to_other_tsl"]))
    
        Pointer.set_ServiceDigitalIdentities(ServiceDigitalIdentities)

    #additional Info
    
    #TSLTypeAdditionalInformation
    TSLTypeAdditionalInformation.original_tagname_="TSLType"
    TSLTypeAdditionalInformation.valueOf_="http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"

    objecttest.valueOf_=TSLTypeAdditionalInformation
    AdditionalInfo.add_OtherInformation(objecttest)

    #SchemeNameOperatorAdditionalInformation
    #for cycle
    schemeNametest.add_Name(test.MultiLangNormStringType("en","uga"))

    testes.SchemeOperatorName=schemeNametest

    AdditionalInfo.add_OtherInformation(testes)

    #SchemeTerritoryAdditionalInformatio

    testes.SchemeTerritory="PT"

    AdditionalInfo.add_OtherInformation(testes)


    #SchemeTypeCommunityRules
    schemetypeCommunityRules_add.original_tagname_="SchemeTypeCommunityRules"
    objecttest.original_tagname_="SchemeTypeCommunityRules"

    #for cycle
    for tsl_data in tsl_list: 
        schemetypeCommunityRules_add.add_URI(test.NonEmptyMultiLangURIType("en", tsl_data["SchemeTypeCommunityRules"]))

        objecttest.valueOf_=schemetypeCommunityRules_add

        AdditionalInfo.add_OtherInformation(objecttest)

    #MimeType
    ObjectType.set__prefix("ns3")
    ObjectType.set_valueOf_("application/vnd.etsi.tsl+xml")

    objectMimeType.set_valueOf_(ObjectType)

    AdditionalInfo.add_OtherInformation(objectMimeType)

    Pointer.TSLLocation=test.NonEmptyURIType("https://trustedlist.eudiw.dev/tools/lotl/eu-lotl.xml")

    Pointer.AdditionalInformation=AdditionalInfo
    Pointers.add_OtherTSLPointer(Pointer)
    
    schemeInfo.PointersToOtherTSL=Pointers
    
    for tsl_data in tsl_list: 
        schemeInfo.set_ListIssueDateTime=tsl_data["issue_date"]
    
    #Next Update
    for tsl_data in tsl_list: 
        NUpdate.set_dateTime(tsl_data["next_update"])
        schemeInfo.NextUpdate= NUpdate

    #DistribuitionPoints

    #for cycle
    
    for tsl_data in tsl_list: 
        URIDP.add_URI(test.NonEmptyURIType(tsl_data["DistributionPoints"]))

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