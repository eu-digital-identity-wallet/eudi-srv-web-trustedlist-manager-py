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
This EJBCA_and_DB.py file contains functions related to add data to DB.
"""

import base64
import binascii
import io
import json
import os
from uuid import uuid4
import uuid
from app import logger
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
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, func_get_user_id_by_hash_pid: {e}", extra=extra)
        print(f"Error processing the form, func_get_user_id_by_hash_pid: {e}")

    return user_id

def getTrustManagerOfCACertificate(ManagementCA):

    try:         
        with open(ManagementCA) as pem_file:

            pem_data = pem_file.read()

            pem_data=pem_data.encode()

            certificate = x509.load_pem_x509_certificate(pem_data, default_backend())

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
        logger.error(f"TTrustedCA Error: An unexpected error occurred.\n {e}rustedCA Error: file not found.\n {e}", extra=extra)
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
            user_id = db.insert_user(hash_pid, user_name, issuing_country, country_id, log_id) 
        
            if not user_id:
                extra = {'code': log_id} 
                logger.info(f"Error creating user.", extra=extra)

                return "Error creating user.", 500
            return user_id, 1
        else:
            user_id = aux
            return user_id, 0
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, user_db: {e}", extra=extra)
        print(f"Error processing the form, user_db: {e}")
        return "Error processing the form.", 500
    
def get_data_op(id, log_id):
    try:
        check = db.get_data_op(id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_op: {e}", extra=extra)
        print(f"Error processing the form, get_data_op: {e}")
        return "Error processing the form.", 500

def get_data_op_edit(id, log_id):
    try:
        check = db.get_data_op_edit(id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_op_edit: {e}", extra=extra)
        print(f"Error processing the form, get_data_op_edit: {e}")
        return "Error processing the form.", 500
    
def update_db_info(current_data_operator_name, current_data_postal_address, current_data_electronicAddress, id, log_id):
    try:
        check = db.update_data_op(current_data_operator_name, current_data_postal_address, current_data_electronicAddress, id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, update_db_info: {e}", extra=extra)
        print(f"Error processing the form, update_db_info: {e}")
        return "Error processing the form.", 500
    

def user_db_info(role, operator_name, PostalAddress, electronicAddress, id, log_id):
    try:
        check = db.insert_user_info(role, operator_name, PostalAddress, electronicAddress, id, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, user_db_info: {e}", extra=extra)
        print(f"Error processing the form, user_db_info: {e}")
        return "Error processing the form.", 500

def check_country(user_country, log_id):
    try:
        check = db.check_country(user_country, log_id)

        return check

    except Exception as e:
            
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, check_country: {e}", extra=extra)
        print(f"Error processing the form, check_country: {e}")
        return "Error processing the form.", 500
    
def tsl_db_info(user_id, Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang,
             PolicyOrLegalNotice_lang, PointerstootherTSL, 
                DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, schemeTerritory, country, log_id):
    try:
        check = db.insert_tsl_info(user_id, Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang,
                             PolicyOrLegalNotice_lang, PointerstootherTSL, 
                             DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, schemeTerritory, country, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, tsl_db_info: {e}", extra=extra)
        print(f"Error processing the form, tsl_db_info: {e}")
        return "Error processing the form.", 500
    
def check_role_user(id, log_id):
    try:
        check = db.check_role_user(id, log_id)
        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, check_role_user: {e}", extra=extra)
        print(f"Error processing the form, check_role_user: {e}")
        return "Error processing the form.", 500

 
def tsp_db_info(user_id, name, trade_name, PostalAddress, EletronicAddress, TSPInformationURI,  log_id):
    try:
        check = db.insert_tsp_info(user_id, name, trade_name, PostalAddress, EletronicAddress, TSPInformationURI, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, tsp_db_info: {e}", extra=extra)
        print(f"Error processing the form, tsp_db_info: {e}")
        return "Error processing the form.", 500
    
def get_data_tsp(tsp_id,  log_id):
    try:
        check = db.get_data_tsp(tsp_id, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_tsp: {e}", extra=extra)
        print(f"Error processing the form, get_data_tsp: {e}")
        return "Error processing the form.", 500
    

def tsp_db_lang(id, tsp_id, current_data_name, current_data_trade_name, current_data_postal_address,
                             current_data_EletronicAddress, current_data_TSPInformationURI,  log_id):
    try:
        check = db.update_data_tsp(tsp_id, current_data_name, current_data_trade_name, current_data_postal_address,
                             current_data_EletronicAddress, current_data_TSPInformationURI, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, tsp_db_lang: {e}", extra=extra)
        print(f"Error processing the form, tsp_db_lang: {e}")
        return "Error processing the form.", 500
    

def service_db_info(user_id, ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, qualifier, log_id):
    try:
        check = db.insert_service_info(user_id, ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, qualifier, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, service_db_info: {e}", extra=extra)
        print(f"Error processing the form, service_db_info: {e}")
        return "Error processing the form.", 500

def get_data_service(service_id, log_id):
    try:
        check = db.get_data_service(service_id, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_service: {e}", extra=extra)
        print(f"Error processing the form, get_data_service: {e}")
        return "Error processing the form.", 500

def service_db_lang(service_id, current_data_ServiceName, current_data_SchemeServiceDefinitionURI, log_id):
    try:
        check = db.update_data_service(service_id, current_data_ServiceName, current_data_SchemeServiceDefinitionURI, log_id) 

        return check
    
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, service_db_lang: {e}", extra=extra)
        print(f"Error processing the form, service_db_lang: {e}")
        return "Error processing the form.", 500
    
def edit_op_db_info(grouped, user_id, log_id):
    try:
        check = db.edit_op(grouped, user_id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, edit_op_db_info: {e}", extra=extra)
        print(f"Error processing the form, edit_op_db_info: {e}")
        return "Error processing the form.", 500
    
def get_tsl_info(id, log_id):
    try:

        check = db.get_user_tsl(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_info: {e}")
        return "Error processing the form.", 500
    

def get_user_info(id, log_id):
    try:
        
        user_info = db.get_user(id, log_id)
        
        if user_info is None:
            return None
        else:
            return user_info
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_user_info: {e}", extra=extra)
        print(f"Error processing the form, get_user_info: {e}")
        return "Error processing the form.", 500
    
def tsl_info(id, log_id):
    try:
        tsl = db.get_tsl(id, log_id)
        if tsl is None:
            return None
        else:
            return tsl
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, tsl_info: {e}", extra=extra)
        print(f"Error processing the form, tsl_info: {e}")
        return "Error processing the form.", 500
    

def get_tsp_info(user_id, log_id):
    try:
        tsp = db.get_tsp(user_id, log_id)
        if tsp is None:
            return "err"
        else:
            return tsp
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsp_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsp_info: {e}")
        return "Error processing the form.", 500

def get_service_info(user_id, log_id):
    try:
        service = db.get_service(user_id, log_id)
        if service is None:
            return "err"
        else:
            return service
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_service_info: {e}", extra=extra)
        print(f"Error processing the form, get_service_info: {e}")
        return "Error processing the form.", 500


def get_data_tsl_edit(tsl_id, log_id):
    try:
        check = db.get_data_edit_tsl(tsl_id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_tsl_edit: {e}", extra=extra)
        print(f"Error processing the form, get_data_tsl_edit: {e}")
        return "Error processing the form.", 500
    
def edit_tsl_db_info(grouped, tsl_id, log_id):
    try:
        check = db.edit_tsl(grouped, tsl_id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, edit_tsl_db_info: {e}", extra=extra)
        print(f"Error processing the form, edit_tsl_db_info: {e}")
        return "Error processing the form.", 500
    
def get_data_tsp_edit(tsp_id, log_id):
    try:
        check = db.get_data_tsp_edit(tsp_id, log_id) 
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_tsp_edit: {e}", extra=extra)
        print(f"Error processing the form, get_data_tsp_edit: {e}")
        return "Error processing the form.", 500


def edit_tsp_db_info(grouped, tsp_id, log_id):
    try:
        check = db.edit_tsp(grouped, tsp_id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, edit_tsp_db_info: {e}", extra=extra)
        print(f"Error processing the form, edit_tsp_db_info: {e}")
        return "Error processing the form.", 500


def get_data_service_edit(service_id, log_id):
    try:
        check = db.get_data_service_edit(service_id, log_id) 
        
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_data_service_edit: {e}", extra=extra)
        print(f"Error processing the form, get_data_service_edit: {e}")
        return "Error processing the form.", 500
    

def edit_service_db_info(grouped, service_id, log_id):
    try:
        check = db.edit_service(grouped, service_id, log_id)
        return check
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, edit_service_db_info: {e}", extra=extra)
        print(f"Error processing the form, edit_service_db_info: {e}")
        return "Error processing the form.", 500
    
def get_service_update(id, log_id):
    try:

        check = db.get_service_update(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_service_update: {e}", extra=extra)
        print(f"Error processing the form, get_service_update: {e}")
        return "Error processing the form.", 500

def update_service(service_id, tsp_id, log_id):
    try:
        check = db.update_service(service_id, tsp_id, log_id)
        return check
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, update_service: {e}", extra=extra)
        print(f"Error processing the form, update_service: {e}")
        return "Error processing the form.", 500


def get_tsp_update(id, log_id):
    try:

        check = db.get_tsp_update(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsp_update: {e}", extra=extra)
        print(f"Error processing the form, get_tsp_update: {e}")
        return "Error processing the form.", 500
    
def update_tsp(tsp_id, tsl_id, log_id):
    try:
        check = db.update_tsp(tsp_id, tsl_id, log_id)
        return check
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, update_tsp: {e}", extra=extra)
        print(f"Error processing the form, update_tsp: {e}")
        return "Error processing the form.", 500

def get_tsl_xml(id, log_id):
    try:

        check = db.get_tsl_xml(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_xml: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_xml: {e}")
        return "Error processing the form.", 500
    
def get_tsp_info_xml(tsl_id, log_id):
    try:
        tsp = db.get_tsp_xml(tsl_id, log_id)
        if tsp is None:
            return None
        else:
            return tsp
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsp_info_xml: {e}", extra=extra)
        print(f"Error processing the form, get_tsp_info_xml: {e}")
        return "Error processing the form.", 500

def get_service_info_xml(tsp_id, log_id):
    try:
        service = db.get_service_xml(tsp_id, log_id)
        if service is None:
            return None
        else:
            return service
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_service_info_xml: {e}", extra=extra)
        print(f"Error processing the form, get_service_info_xml: {e}")
        return "Error processing the form.", 500
    
def check_tsl(tsl_id, log_id):
    try:
        
        tsp_id = db.check_tsp(tsl_id, log_id)
        if tsp_id is None:
            return "tsp"
        else:
            for item in tsp_id:
                value = item[0]
                service_id = db.check_service(value, log_id)
            
            if service_id is None:
                return "service"
            else:
                return "ok"
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, check_tsl: {e}", extra=extra)
        print(f"Error processing the form, check_tsl: {e}")
        return "Error processing the form.", 500
    
def update_lotl(id, log_id):
    try:

        check = db.update_lotl(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_info: {e}")
        return "Error processing the form.", 500

def update_not_seleted_lotl(id, log_id):
    try:

        check = db.update_not_selected_lotl(id, log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_info: {e}")
        return "Error processing the form.", 500

def get_all_tsls_ids(log_id):
    try:

        check = db.get_tsls_ids(log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_info: {e}")
        return "Error processing the form.", 500

def get_tsl_loft(log_id):
    try:
        tsl = db.get_tsl_loft(log_id)
        if tsl is None:
            return None
        else:
            return tsl
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, tsl_info: {e}", extra=extra)
        print(f"Error processing the form, tsl_info: {e}")
        return "Error processing the form.", 500
    
def get_lotl_tsl_info(log_id):
    try:

        check = db.get_lotl_tsl(log_id)
        
        if(check != None):
            return check
        else:
            return ("err")
        
    except Exception as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error processing the form, get_tsl_info: {e}", extra=extra)
        print(f"Error processing the form, get_tsl_info: {e}")
        return "Error processing the form.", 500
    
