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
This EJBCA_and_DB.py file contains functions related to generation of the Certificate Request Info and add data to DB.
"""

import base64
import binascii
import io
import json
import os
from uuid import uuid4
import uuid
import cbor2
from flask import (
    Blueprint,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)
import segno
import requests
from requests.auth import HTTPBasicAuth
import cbor2
import ssl

# from . import oidc_metadata
import base64
import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from requests_pkcs12 import Pkcs12Adapter
import models as db
import user as get_hash_user_pid


def func_get_user_id_by_hash_pid(hash_pid, log_id):

    try:
        user_id =db.get_user_id_by_hash_pid(hash_pid, log_id)
    except Exception as e:
        #extra = {'code': log_id} 
        #logger.error(f"User doesn't exist!", extra=extra)
        print("User doesn't exist!")

    return user_id

def getTrustManagerOfCACertificate(ManagementCA):

    try:         
        with open(ManagementCA) as pem_file:

            pem_data = pem_file.read()

            pem_data=pem_data.encode()

            certificate = x509.load_pem_x509_certificate(pem_data, default_backend())

    except FileNotFoundError as e:
        #extra = {'code':'-'} 
        #logger.error(f"TrustedCA Error: file not found.\n {e}", extra=extra)
        print(f"TrustedCA Error: file not found.\n {e}")
    except json.JSONDecodeError as e:
       #extra = {'code':'-'} 
        #logger.error(f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}", extra=extra)
        print(f"TrustedCA Error: Metadata Unable to decode JSON.\n {e}")
    except Exception as e:
        #extra = {'code':'-'} 
        #logger.error(f"TTrustedCA Error: An unexpected error occurred.\n {e}rustedCA Error: file not found.\n {e}", extra=extra)
        print(f"TrustedCA Error: An unexpected error occurred.\n {e}")

    return certificate


def http_post_requests_with_custom_ssl_context(trust_manager, key_manager_filepath, key_manager_password, url, json_body, headers):

    # ssl_context = ssl.SSLContext()
    # ssl_context.load_verify_locations(trust_manager)
    # ssl_context.verify_mode=ssl.CERT_REQUIRED

    # http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ssl_context=ssl_context)

    # # Set up the requests session
    session = requests.Session()
    session.mount('https://', Pkcs12Adapter(pkcs12_filename=key_manager_filepath, pkcs12_password=key_manager_password))

    # Perform the POST request
    response = session.post(url, json=json_body, headers=headers, verify=False)

    return response


def user_db(user, user_name, country_id, log_id):

    givenName=user["given_name"]
    surname=user["family_name"]
    birth_date=user["birth_date"]
    issuing_country=user["issuing_country"]
    issuance_authority=user["issuing_authority"]

    try:

        new_user = get_hash_user_pid.User(surname, givenName, birth_date, issuing_country, issuance_authority)
        hash_pid = new_user.hash

        aux = db.check_user(hash_pid, log_id)

        if(aux == None):
            user_id = db.insert_user(hash_pid, user_name, country_id, log_id) 
        
            if not user_id:
                # extra = {'code': log_id} 
                # logger.info(f"Error creating user.", extra=extra)

                return "Error creating user.", 500
            return user_id, 1
        else:
            user_id = aux
            return user_id, 0
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    

def user_db_info(role, opName_en, address, locality, stateProvince, postalCode, electronicAddress, id, log_id):
    try:
        check = db.insert_user_info(role, opName_en, address, locality, stateProvince, postalCode, electronicAddress, id, log_id) 

        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500

def check_country(user_country, log_id):
    try:
        check = db.check_country(user_country, log_id)

        return check

    except Exception as e:
            
            # extra = {'code': log_id} 
            # logger.error(f"Error processing the form: {e}", extra=extra)

            print(f"Error processing the form: {e}")
            return "Error processing the form.", 500
    
def tsl_db_info(Version, Sequence_number, TSLType, SchemeName_lang, SchemeName_en, Uri_lang,Uri_en, SchemeTypeCommunityRules_lang,
                SchemeTypeCommunityRules_en, PolicyOrLegalNotice_lang, PolicyOrLegalNotice_en, PointerstootherTSL, 
                DistributionPoints, Issue_date, NextUpdate, Status, Signature, AdditionalInformation, country, log_id):
    try:
        check = db.insert_tsl_info(Version, Sequence_number, TSLType, SchemeName_lang, SchemeName_en, Uri_lang,Uri_en, SchemeTypeCommunityRules_lang,
                             SchemeTypeCommunityRules_en, PolicyOrLegalNotice_lang, PolicyOrLegalNotice_en, PointerstootherTSL, 
                             DistributionPoints, Issue_date, NextUpdate, Status, Signature, AdditionalInformation, country, log_id) 

        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    
    
def update_user_tsl(id, check,  log_id):
    try:
        check = db.update_user_tsl(id, check, log_id) 

        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500


def check_role_user(id, log_id):
    try:
        check = db.check_role_user(id, log_id)
        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500

 
def tsp_db_info(id, name, trade_name, StreetAddress, Locality, StateOrProvince, PostalCode, 
                             CountryName, EletronicAddress, TSPInformationURI, country,  log_id):
    try:
        check = db.get_user_tsl(id, log_id)
        check = db.insert_tsp_info(check, name, trade_name, StreetAddress, Locality, StateOrProvince, PostalCode, 
                             CountryName, EletronicAddress, TSPInformationURI, country, log_id) 

        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    

def service_db_info(id, service_type, service_name_lang, service_name_en, qualifier, digital_identity, status, status_start_date, uri, log_id):
    try:
        check = db.get_user_tsl(id, log_id)
        check = db.get_tsp_tsl(check, log_id)
        check = db.insert_service_info(check, service_type, service_name_lang, service_name_en, qualifier, digital_identity, status, status_start_date, uri, log_id) 

        return check
    
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    
def get_tsl_info(id, log_id):
    try:

        check = db.get_user_tsl(id, log_id)
        
        if(check != None):
            tsl = db.get_tsl(check, log_id)
            return tsl
        else:
            return None
        
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    

def get_user_info(id, log_id):
    try:
        
        user_info = db.get_user(id, log_id)
        
        if user_info is None:
            return None
        else:
            return user_info
        
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    
def tsl_info(id, log_id):
    try:
        tsl = db.get_tsl(id, log_id)
        if tsl is None:
            return None
        else:
            return tsl
        
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500
    

def get_tsp_info(id, log_id):
    try:
        tsp = db.get_tsp(id, log_id)
        if tsp is None:
            return None
        else:
            return tsp
        
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500

def get_service_info(id, log_id):
    try:
        service = db.get_service(id, log_id)
        if service is None:
            return None
        else:
            return service
        
    except Exception as e:
        
        # extra = {'code': log_id} 
        # logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error processing the form: {e}")
        return "Error processing the form.", 500