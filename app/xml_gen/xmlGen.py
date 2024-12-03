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
import datetime
from io import StringIO
import xml.etree.ElementTree as xml
from dateutil.relativedelta import relativedelta
from signxml import DigestAlgorithm
from signxml.xades import (XAdESSigner, XAdESSignaturePolicy, XAdESDataObjectFormat)
import xml_gen.trustedlists_api as test
from signxml import DigestAlgorithm
from signxml.xades import (XAdESSigner, XAdESSignaturePolicy, XAdESDataObjectFormat)
from xml_gen.xml_config import ConfXML as confxml
from signxml import XMLSigner, algorithms

def xml_gen(PostalAddress, dictFromDB_scheme_operator, dictFromDB_trusted_lists, dictFromDB_trust_services, dictFromDB_trust_service_providers):
    
    PostalAddresses=PostalAddress
    root=test.TrustStatusListType()

    root.set_TSLTag("http://uri.etsi.org/19612/TSLTag")
    root.set_Id("TrustServiceStatusList")

    schemeInfo = test.TSLSchemeInformationType()

    schemeInfo.TSLVersionIdentifier=dictFromDB_trusted_lists["Version"]
    schemeInfo.TSLSequenceNumber=dictFromDB_trusted_lists["SequenceNumber"] + 1
    TSLType=test.NonEmptyURIType()
    TSLType.set_valueOf_(dictFromDB_trusted_lists["TSLType"])
    schemeInfo.TSLType=TSLType

    #schemeOperatorName

    schemeOName = test.InternationalNamesType()

    #for cycle
    schemeOName.add_Name(test.MultiLangNormStringType("en",dictFromDB_scheme_operator["operator_name"]))

    schemeInfo.SchemeOperatorName=schemeOName

    #Scheme Operator Address
    schemeOAddress= test.AddressType()

    eletronic=test.ElectronicAddressType()

    #for cycle
    eletronic.add_URI(test.NonEmptyMultiLangURIType("en",dictFromDB_scheme_operator["EletronicAddress"]))
    #----------------------------------------------------#
    schemeOAddress.set_ElectronicAddress(eletronic)

    PostalAdresses=test.PostalAddressListType()

    #for cycle for postal address
    postal=test.PostalAddressType()
    postal.set_lang("en")
    postal.set_CountryName(dictFromDB_scheme_operator["country"])
    postal.set_Locality(dictFromDB_scheme_operator["Locality"])
    postal.set_StateOrProvince(dictFromDB_scheme_operator["StateOrProvince"])
    postal.set_PostalCode(dictFromDB_scheme_operator["PostalCode"])
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
    schemeInfo.set_SchemeTerritory(dictFromDB_scheme_operator["country"])

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
    
    schemeInfo.ListIssueDateTime=dictFromDB_trusted_lists["issue_date"]
    
    #Next Update
    NUpdate=test.NextUpdateType()
    NUpdate.dateTime=dictFromDB_trusted_lists["next_update"]
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
    TSPName.add_Name(test.MultiLangNormStringType("en", dictFromDB_trust_service_providers["name"]))
    
    TSPTradeName= test.InternationalNamesType()
    TSPTradeName.add_Name(test.MultiLangNormStringType("en", dictFromDB_trust_service_providers["trade_name"]))

    TSPAddress=test.AddressType()

    TSPPostalAddress=test.PostalAddressListType()
    postal1=test.PostalAddressType()
    postal1.set_CountryName(dictFromDB_trust_service_providers["country"])
    postal1.set_Locality(dictFromDB_trust_service_providers["Locality"])
    postal1.set_StateOrProvince(dictFromDB_trust_service_providers["StateOrProvince"])
    postal1.set_PostalCode(dictFromDB_trust_service_providers["PostalCode"])
    TSPPostalAddress.add_PostalAddress(postal1)

    TSPEletronicAddress=test.ElectronicAddressType()
    TSPEletronicAddress.add_URI(test.NonEmptyMultiLangURIType("en",dictFromDB_trust_service_providers["EletronicAddress"]))

    TSPAddress.set_ElectronicAddress(TSPEletronicAddress)
    TSPAddress.set_PostalAddresses(TSPPostalAddress)

    TSPInformationURI= test.NonEmptyMultiLangURIListType()
    TSPInformationURI.add_URI(test.NonEmptyMultiLangURIType("en",dictFromDB_trust_service_providers["TSPInformationURI"]))

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
    ServiceInformation.set_ServiceTypeIdentifier(test.NonEmptyURIType(dictFromDB_trust_services["service_type"]))

    ServiceName=test.InternationalNamesType()
    ServiceName.add_Name(test.MultiLangNormStringType("en", dictFromDB_trust_services["service_name"]))
    ServiceInformation.set_ServiceName(ServiceName)

    ServiceDigitalIdentity=test.ServiceDigitalIdentityListType()
    ServiceDigitalIdentity.add_ServiceDigitalIdentity(test.DigitalIdentityType(dictFromDB_trust_services["digital_identity"]))
    ServiceInformation.set_ServiceDigitalIdentity(ServiceDigitalIdentities)

    ServiceInformation.set_ServiceStatus(test.NonEmptyURIType(dictFromDB_trust_services["status"]))
    ServiceInformation.set_StatusStartingTime(datetime.datetime.now(datetime.timezone.utc))

    SchemeServiceDefinitionURI=test.NonEmptyMultiLangURIListType()
    SchemeServiceDefinitionURI.add_URI(test.NonEmptyMultiLangURIType("en",dictFromDB_trust_services["SchemeServiceDefinitionURI"]))
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
    qualifier.set_uri("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement")
    qualifiers.add_Qualifier(qualifier)

    #for cycle
    CriteriaList=test.CriteriaListType()

    PolicySet=test.PoliciesListType()

    #for cycle
    PolicyIdentifier=test.ObjectIdentifierType()
    Identifier=test.IdentifierType(test.QualifierType().set_uri("teste.pt"))
    PolicyIdentifier.set_Identifier(Identifier)

    PolicySet.add_PolicyIdentifier(PolicyIdentifier)

    CriteriaList.add_PolicySet(PolicySet)

    qualificationElement.set_CriteriaList(CriteriaList)


    #AdditionalServiceInformation		
    AdditionalServiceInformation=test.AdditionalServiceInformationType()
    AdditionalServiceInformation.set_URI(test.NonEmptyMultiLangURIType("en","	https://www.teste.com"))
    Extension.set_anytypeobjs_(AdditionalServiceInformation)
    Extension.set_Critical(True)

    ServiceInformationExtensions.add_Extension(Extension)
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
    rootTemp=xml.fromstring(xml_string)

    signature_policy = XAdESSignaturePolicy(
        Identifier="MyPolicyIdentifier",
        Description="Hello XAdES",
        DigestMethod=DigestAlgorithm.SHA256,
        DigestValue="Ohixl6upD6av8N7pEvDABhEL6hM=",
    )
    data_object_format = XAdESDataObjectFormat(
        Description="My XAdES signature",
        MimeType="text/xml",
    )
    signer = XAdESSigner(
        signature_policy=signature_policy,
        claimed_roles=["signer"],
        data_object_format=data_object_format,
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    )

    signed_root = XMLSigner(signature_algorithm=algorithms.SignatureMethod.ECDSA_SHA256).sign(data=rootTemp, key=key, cert=cert)
    #verified_data = XMLVerifier().verify(signed_root)

    # with open ("teste.xml", "w") as file: 
    #     signed_root.write(file, level=0) 
    
    
    tree = xml.ElementTree(signed_root) 
      
    with open ("xmlTest.xml", "wb") as files : 
        tree.write(files)


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
    #     "digital_identity" :b"MIIICDCCBfCgAwIBAgIUSOnGJxOHWc5N+Nk12eZPPCwr7ZYwDQYJKoZIhvcNAQENBQAwXzELMAkGA1UEBhMCUFQxKjAoBgNVBAoMIURpZ2l0YWxTaWduIENlcnRpZmljYWRvcmEgRGlnaXRhbDEkMCIGA1UEAwwbRElHSVRBTFNJR04gUVVBTElGSUVEIENBIEcxMB4XDTI0MDUwNjEyNDUxNloXDTI3MDUwNjEyNDUxNlowggFZMQswCQYDVQQGEwJFUzE9MDsGA1UECww0Q2VydGlmaWNhdGUgUHJvZmlsZSAtIFF1YWxpZmllZCBDZXJ0aWZpY2F0ZSAtIE1lbWJlcjEjMCEGA1UEYQwaTEVJWEctMjU0OTAwWk5ZQTFGTFVROVUzOTMxHDAaBgNVBAoME0VVUk9QRUFOIENPTU1JU1NJT04xKTAnBgNVBAsMIEVudGl0bGVtZW50IC0gRUMgU1RBVFVUT1JZIFNUQUZGMTIwMAYJKoZIhvcNAQkBFiN2aWNlbnRlLmFuZHJldS1uYXZhcnJvQGVjLmV1cm9wYS5ldTEXMBUGA1UEBAwOQU5EUkVVIE5BVkFSUk8xEDAOBgNVBCoMB1ZJQ0VOVEUxHTAbBgNVBAsMFFJlbW90ZVFTQ0RNYW5hZ2VtZW50MR8wHQYDVQQDDBZWSUNFTlRFIEFORFJFVSBOQVZBUlJPMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAveJV7goW3mvqJq2kMT0cnrkFAnT/lyzbgaHVvd5jEMHy6RyoI1Af4JTlOWSjC+6fsNzApFR1Tv3w8/WuSgjHTWfDnpqs20iJh979A5WwvfXuzcuUqeFFptdR/tJm/08TsTAD+CeA+rQo6K23B1xMYRwX/BNt/EL03Q/TOQj5V4uV3Kyf0945yu5gOhmrMs/RZCZ8M+iahwTaVktf+ZvhocSsPt+a2OuPI8IpTU+xIWAXWuQ+27Q7zzD0d6sqBdruDr16clFtZXWNRikm9q6pCOAOKG/myszeUuy++TPtQnI3+OQlTuyDXsz9UNKboQCF2SNmfRoeBxcx02tS/zUgPwIDAQABo4ICvjCCArowDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRzSfFAHBQEfJoSf/ovzVxnIxjpFDCBhgYIKwYBBQUHAQEEejB4MEYGCCsGAQUFBzAChjpodHRwczovL3FjYS1nMS5kaWdpdGFsc2lnbi5wdC9ESUdJVEFMU0lHTlFVQUxJRklFRENBRzEucDdiMC4GCCsGAQUFBzABhiJodHRwczovL3FjYS1nMS5kaWdpdGFsc2lnbi5wdC9vY3NwMC4GA1UdEQQnMCWBI3ZpY2VudGUuYW5kcmV1LW5hdmFycm9AZWMuZXVyb3BhLmV1MF8GA1UdIARYMFYwNwYLKwYBBAGBx3wEAQEwKDAmBggrBgEFBQcCARYaaHR0cHM6Ly9wa2kuZGlnaXRhbHNpZ24ucHQwEAYOKwYBBAGBx3wEAgEBAQQwCQYHBACL7EABAjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwSwYDVR0fBEQwQjBAoD6gPIY6aHR0cHM6Ly9xY2EtZzEuZGlnaXRhbHNpZ24ucHQvRElHSVRBTFNJR05RVUFMSUZJRURDQUcxLmNybDAdBgNVHQ4EFgQUjueweY4PI0KGjetMh84vTsEnxQcwDgYDVR0PAQH/BAQDAgZAMIHTBggrBgEFBQcBAwSBxjCBwzAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYBMGoGBgQAjkYBBTBgMC4WKGh0dHBzOi8vcWNhLWcxLmRpZ2l0YWxzaWduLnB0L1BEU19wdC5wZGYTAnB0MC4WKGh0dHBzOi8vcWNhLWcxLmRpZ2l0YWxzaWduLnB0L1BEU19lbi5wZGYTAmVuMBUGCCsGAQUFBwsCMAkGBwQAi+xJAQEwFQYIKwYBBQUHCwIwCQYHBACL7EkBAjANBgkqhkiG9w0BAQ0FAAOCAgEAHBjW4N8NKNCiJot414m/L76pB/15LKiGDi1/2V7MHe8u2GcplR1IjESrSEhhwUAW1hwDIK9xJrJ/hdDUMIQcKScSiJCqTCb0Yk39yj/gfOYaN/3fqw8Pjh9k++3Ox7KnvY3R/foFvGJlyiuqaai/JgBmc4qDBHSIDyo5gRw6v70osRPDR5sJs4Xh3FOJn9Y0JZPLF/skYtLrNVysL/4A4bbAxB2DcJ5MpoIegh/fnJ5s2BOVq2Xq8ADpeJoLFYbtlbP7NwsGgew2wKiDW963MlJL/Xa2AqcPVE/UnXFkIBCwZH+covxSEQH2iVcF8cEDHBiYHGERaSmL/uHK/F8soDO9VQwtKNxsiIKAWsQHTYcKfEgVuweyLj7TsCmh6T4pIHqaNDqWvrgEIo0ZwuBmfXVEd+JMSzSgIcJ2bPR2KNoJ14MO4FFYdAAnVlfdhipErsK6R23hlto7b3XKiMRUt9xrvPUjuEJdGI5hPm9CqGK1GxlRoKLewyX7A+OIcPMPu1KfuuUTUn+3hLJJZO5H9k4uVMJ/FOhwzc2VhRpyvNjfmFZksFvseFGvMl5EWIqp3JCo0ItkOBG59ulBwg/99Y0pT6LW9cviTzKIwDtHmQrIgYLa+lCYwWdGhIidXynvLpWiVRZJvYrPIGpzQCRcw9V2i8zT7nksj7QF9v88kto=",
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