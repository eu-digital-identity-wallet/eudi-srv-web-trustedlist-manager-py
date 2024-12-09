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

    secret_key = "secret_key"

    #service_url = "http://127.0.0.1:5000/"
    service_url = "https://registry.serviceproviders.eudiw.dev/"

    #trusted_CAs_path = "app\certs"
    trusted_CAs_path = "/etc/eudiw/pid-issuer/cert/"

    deffered_expiry = 100

    #log_dir = "app\logs"
    log_dir = "app/logs"

    roles = {
      "tsl_op":"TSL Operator",
      "tsp_op":"TSP Operator"
    }

    qualifiers = {
      "QCForESig": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig",
      "QCStatement": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement",
      "QCQSCDStatusAsInCert": "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"
    }


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