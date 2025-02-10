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
"""
This config.py contains configuration data for the age-over-poc Web service. 

NOTE: You should only change it if you understand what you're doing.
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from flask import  session
import logging
from logging.handlers import TimedRotatingFileHandler


class ConfService:
    
    two_operators = False

    secret_key = "secret_key"

    #service_url = "http://127.0.0.1:5000/"
    service_url = "https://trustedlist.serviceproviders.eudiw.dev/"

    #trusted_CAs_path = "app\certs"
    trusted_CAs_path = "/etc/eudiw/pid-issuer/cert/"

    deffered_expiry = 100

    #log_dir = "app/logs"
    log_dir = "app\logs"
    
    #cert_UT = "app/xml_gen/cert_UT.pem"
    cert_UT = "/etc/eudiw/pid-issuer/cert/PID-DS-0001_UT_cert.der"

    #priv_key_UT = "app/xml_gen/privkey_UT.pem"
    priv_key_UT = "/etc/eudiw/pid-issuer/privkey/PID-DS-0001_UT.pem"

    roles = {
      "tsl_op":"TSL Operator",
      "tsp_op":"TSP Operator"
    }

    qualifiers = {
      "QCForESig": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig",
      "QCStatement": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement",
      "QCQSCDStatusAsInCert": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"
    }


    url_verifier="verifier-backend.eudiw.dev"

    lang = {
      "Portugues": "pt", 
      "English": "en"
    }

    SchemeTypeCommunityRules ={
      "Eu Common": "https://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon/", 
      "Scheme Territory": "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/"
    }

    #Service Identifiers
    service_category = {
      "Qualified": "qualified", 
      "Non Qualified": "non_qualified", 
      "National": "national"
    }

    qualified=["http://uri.etsi.org/TrstSvc/Svctype/CA/QC","http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
               "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC","http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
               "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q","http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q",
               "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q", "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q",
               "http://uri.etsi.org/TrstSvc/Svctype/RemoteQSigCDManagement/Q", "http://uri.etsi.org/TrstSvc/Svctype/RemoteQSealCDManagement/Q",
               "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q","http://uri.etsi.org/TrstSvc/Svctype/ElectronicArchiving/Q",
               "http://uri.etsi.org/TrstSvc/Svctype/Ledgers/Q"]

    non_qualified=["http://uri.etsi.org/TrstSvc/Svctype/CA/PKC","http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
                   "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL","http://uri.etsi.org/TrstSvc/Svctype/TSA",
                   "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC","http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
                   "http://uri.etsi.org/TrstSvc/Svctype/EDS", "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM",
                   "http://uri.etsi.org/TrstSvc/Svctype/PSES", "http://uri.etsi.org/TrstSvc/Svctype/AdESValidation",
                   "http://uri.etsi.org/TrstSvc/Svctype/AdESGeneration", "http://uri.etsi.org/TrstSvc/Svctype/RemoteSigCDManagement",
                   "http://uri.etsi.org/TrstSvc/Svctype/RemoteSealCDManagement", "http://uri.etsi.org/TrstSvc/Svctype/EAA",
                   "http://uri.etsi.org/TrstSvc/Svctype/ElectronicArchiving", "http://uri.etsi.org/TrstSvc/Svctype/Ledgers",
                   "http://uri.etsi.org/TrstSvc/Svctype/PKCValidation", "http://uri.etsi.org/TrstSvc/Svctype/PKCPreservation",
                   "http://uri.etsi.org/TrstSvc/Svctype/EAAValidation ", "http://uri.etsi.org/TrstSvc/Svctype/TSTValidation ",
                   "http://uri.etsi.org/TrstSvc/Svctype/EDSValidation" , "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA",
                   "http://uri.etsi.org/TrstSvc/Svctype/Ledgers", "http://uri.etsi.org/TrstSvc/Svctype/PKCValidation",
                   "http://uri.etsi.org/TrstSvc/Svctype/PKCPreservation", "http://uri.etsi.org/TrstSvc/Svctype/EAAValidation" ,
                   "http://uri.etsi.org/TrstSvc/Svctype/TSTValidation" , "http://uri.etsi.org/TrstSvc/Svctype/EDSValidation ",
                   "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA","http://uri.etsi.org/TrstSvc/Svctype/CA/PKC/CertsforOtherTypesOfTS",
                   "http://uri.etsi.org/TrstSvc/Svctype/PKCValidation/CertsforOtherTypesOfTS"]

    national=["http://uri.etsi.org/TrstSvc/Svctype/RA","http://uri.etsi.org/TrstSvc/Svctype/RA/nothavingPKIid","http://uri.etsi.org/TrstSvc/Svctype/ACA",
              "http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority", "http://uri.etsi.org/TrstSvc/Svctype/Archiv",
              "http://uri.etsi.org/TrstSvc/Svctype/Archiv/nothavingPKIid","http://uri.etsi.org/TrstSvc/Svctype/IdV",
              "http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid","http://uri.etsi.org/TrstSvc/Svctype/KEscrow",
              "http://uri.etsi.org/TrstSvc/Svctype/KEscrow/nothavingPKIid","http://uri.etsi.org/TrstSvc/Svctype/PPwd",
              "http://uri.etsi.org/TrstSvc/Svctype/PPwd/nothavingPKIid","http://uri.etsi.org/TrstSvc/Svctype/TLIssuer",
              "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC","http://uri.etsi.org/TrstSvc/Svctype/unspecified"]


    # log_dir = "/tmp/log"
    # #log_dir = "../../log"
    # log_file_info = "logs.log"

    # backup_count = 7

    # log_handler_info = TimedRotatingFileHandler(
    #     filename=f"{log_dir}/{log_file_info}",
    #     when="midnight",  # Rotation midnight
    #     interval=1,  # new file each day
    #     backupCount=backup_count,
    # )

    # log_handler_info.setFormatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    # logger_info = logging.getLogger("info")
    # logger_info.addHandler(log_handler_info)
    # logger_info.setLevel(logging.INFO)

    eu_languages = [
    "bg", "cs", "da", "de", "el", "en", "es", "et", "fi", "fr",
    "ga", "hr", "hu", "it", "lt", "lv", "mt", "nl", "pl", "pt",
    "ro", "sk", "sl", "sv"]
    eu_countries = [
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE"]