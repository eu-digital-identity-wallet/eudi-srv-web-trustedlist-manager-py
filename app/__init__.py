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
import json
import logging
from logging.handlers import TimedRotatingFileHandler
import os
import sys

from requests import Session

from app.app_config.config import ConfService


sys.path.append(os.path.dirname(__file__))


from flask import Flask, render_template
from flask_session import Session
from flask_cors import CORS
from pycose.keys import EC2Key

import os
from flask import Flask
import os

from app_config.config import ConfService as cfgserv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def setup_logger():
    log_dir = cfgserv.log_dir
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file_info = "app_logs.log"
    log_path = os.path.join(log_dir, log_file_info)

    logger = logging.getLogger("app_logger")
    logger.setLevel(logging.INFO)  

    log_handler = TimedRotatingFileHandler(
        filename=log_path,
        when="midnight", 
        interval=1,
        backupCount=7,  
        encoding="utf-8",
        utc=True  
    )

    log_format = "%(asctime)s %(name)s %(levelname)s - Message: %(message)s"
    formatter = logging.Formatter(log_format)
    log_handler.setFormatter(formatter)

    logger.addHandler(log_handler)

    return logger

logger = setup_logger()

def setup_trusted_CAs():
    global trusted_CAs
    
    try:
        ec_keys = {}
        for file in os.listdir(cfgserv.trusted_CAs_path):
            if file.endswith("pem"):
                CA_path = os.path.join(
                    cfgserv.trusted_CAs_path, file
                    
                )

                with open(CA_path) as pem_file:

                    pem_data = pem_file.read()

                    pem_data=pem_data.encode()

                    certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
                    
                    public_key = certificate.public_key()

                    issuer=certificate.issuer

                    not_valid_before=certificate.not_valid_before_utc

                    not_valid_after=certificate.not_valid_after_utc

                    x = public_key.public_numbers().x.to_bytes(
                        (public_key.public_numbers().x.bit_length() + 7) // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    y = public_key.public_numbers().y.to_bytes(
                        (public_key.public_numbers().y.bit_length() + 7) // 8,  # Number of bytes needed
                        "big",  # Byte order
                    )

                    ec_key = EC2Key(x=x, y=y, crv=1)  # SECP256R1 curve is equivalent to P-256
                    
                    ec_keys.update({issuer:{
                        "certificate":certificate,
                        "public_key":public_key,
                        "not_valid_before":not_valid_before,
                        "not_valid_after":not_valid_after,
                        "ec_key":ec_key
                    }})
                    

    except FileNotFoundError as e:
        extra = {'code':'-'} 
        logger.error(f"TrustedCA Error: file not found.\n {e}", extra=extra)
        print(f"TrustedCA Error: file not found.\n {e}")
    except json.JSONDecodeError as e:
        extra = {'code':'-'} 
        logger.error(f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}", extra=extra)
        print(f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}")
    except Exception as e:
        extra = {'code':'-'} 
        logger.error(f"TrustedCA Error: An unexpected error occurred.\n {e}", extra=extra)
        print(f"TrustedCA Error: An unexpected error occurred.\n {e}")

    trusted_CAs=ec_keys

setup_trusted_CAs()


def handle_exception(e):

    return (
        render_template(
            "500.html",
            error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            error_code="Internal Server Error",
        ),
        500,
    )

def page_not_found(e):

    return (
        render_template(
            "500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )

def create_app():

    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = ConfService.secret_key

    #app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    from . import (RPR_routes)

    app.register_blueprint(RPR_routes.rpr)

    # config session
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # CORS is a mechanism implemented by browsers to block requests from domains other than the server's one.
    CORS(app, supports_credentials=True)

    return app