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
This rpr_routes.py file is the blueprint of the Web RelyingParty Registration service.
"""

import base64
import binascii
from datetime import datetime, timedelta
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
    send_file,
    session,
    url_for,
    jsonify
)
import requests

import base64
import urllib.parse
from app_config.config import ConfService as cfgserv
import segno

from app.data_management import oid4vp_requests
from app.validate_vp_token import validate_vp_token, cbor2elems

import user as get_hash_user_pid
import app.EJBCA_and_DB_func as func
from app_config.Crypto_Info import Crypto_Info as crypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from xml_gen.xml_config import ConfXML as confxml
from xml_gen.xmlGen import xml_gen

import datetime
from dateutil.relativedelta import relativedelta

rpr = Blueprint("RPR", __name__, url_prefix="/")

rpr.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')


@rpr.route('/', methods=['GET','POST'])
def initial_page():

    return render_template('initial_page.html', redirect_url= cfgserv.service_url, pid_auth = cfgserv.service_url + "authentication", certificateList=cfgserv.service_url + "authentication_List")


@rpr.route("/authentication", methods=["GET","POST"])
def authentication():

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload ={
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "presentation_definition": {
            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "input_descriptors": [
            {
                "id": "eu.europa.ec.eudi.pid.1",
                "format": {
                "mso_mdoc": {
                    "alg": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "EdDSA"
                    ]
                }
                },
                "name": "EUDI PID",
                "purpose": "We need to verify your identity",
                "constraints": {
                "fields": [
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                    ],
                    "intent_to_retain": False
                    }
                ]
                }
            }
            ]
        }
        }


    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=json.dumps(payload)).json()

    QR_code_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
    )

    payload_sameDevice=payload
    session["session_id"]=str(uuid.uuid4())
    session["certificate_List"]=False

    payload_sameDevice.update({"wallet_response_redirect_uri_template":cfgserv.service_url +
                                                       "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session["session_id"]})

    response_same_device= requests.request("POST", url, headers=headers, data=json.dumps(payload_sameDevice)).json()

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_same_device["client_id"]
        + "&request_uri="
        + response_same_device["request_uri"]
    )

    oid4vp_requests.update({session["session_id"]:{"response": response_same_device, "expires":datetime.datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})


    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(QR_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response["presentation_id"],
        redirect_url= cfgserv.service_url
    )
@rpr.route("/authentication_List", methods=["GET","POST"])
def authentication_List():

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations"
    payload ={
        "type": "vp_token",
        "nonce": "hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc=",
        "presentation_definition": {
            "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
            "input_descriptors": [
            {
                "id": "eu.europa.ec.eudi.pid.1",
                "format": {
                "mso_mdoc": {
                    "alg": [
                    "ES256",
                    "ES384",
                    "ES512",
                    "EdDSA"
                    ]
                }
                },
                "name": "EUDI PID",
                "purpose": "We need to verify your identity",
                "constraints": {
                "fields": [
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['family_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['given_name']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['birth_date']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['age_over_18']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_authority']"
                    ],
                    "intent_to_retain": False
                    },
                    {
                    "path": [
                        "$['eu.europa.ec.eudi.pid.1']['issuing_country']"
                    ],
                    "intent_to_retain": False
                    }
                ]
                }
            }
            ]
        }
        }


    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=json.dumps(payload)).json()

    QR_code_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response["client_id"]
        + "&request_uri="
        + response["request_uri"]
    )

    payload_sameDevice=payload
    session["session_id"]=str(uuid.uuid4())
    session["certificate_List"]=True

    payload_sameDevice.update({"wallet_response_redirect_uri_template":cfgserv.service_url +
                                                       "getpidoid4vp?response_code={RESPONSE_CODE}&session_id=" + session["session_id"]})

    response_same_device= requests.request("POST", url, headers=headers, data=json.dumps(payload_sameDevice)).json()

    deeplink_url = (
        "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id="
        + response_same_device["client_id"]
        + "&request_uri="
        + response_same_device["request_uri"]
    )

    oid4vp_requests.update({session["session_id"]:{"response": response_same_device, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry), "certificate_List":True}})


    # Generate QR code
    # img = qrcode.make("uri")
    # QRCode.print_ascii()

    qrcode = segno.make(QR_code_url)
    out = io.BytesIO()
    qrcode.save(out, kind='png', scale=3)

    """ qrcode.to_artistic(
        background=cfgtest.qr_png,
        target=out,
        kind="png",
        scale=4,
    ) """
    # qrcode.terminal()
    # qr_img_base64 = qrcode.png_data_uri(scale=4)

    qr_img_base64 = "data:image/png;base64," + base64.b64encode(out.getvalue()).decode(
        "utf-8"
    )

    return render_template(
        "pid_login_qr_code.html",
        url_data=deeplink_url,
        qrcode=qr_img_base64,
        presentation_id=response["presentation_id"],
        redirect_url= cfgserv.service_url
    )

@rpr.route("/pid_authorization")
def pid_authorization_get():

    presentation_id= request.args.get("presentation_id")

    url = "https://dev.verifier-backend.eudiw.dev/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}),200
            
    
@rpr.route("/getpidoid4vp", methods=["GET", "POST"])
def getpidoid4vp():

    if "response_code" in request.args and "session_id" in request.args:

        response_code = request.args.get("response_code")
        presentation_id = oid4vp_requests[request.args.get("session_id")]["response"]["presentation_id"]
        session["session_id"]=request.args.get("session_id")
        if oid4vp_requests[request.args.get("session_id")]["certificate_List"] !=None:
            session["certificate_List"]=True
        url = (
            "https://dev.verifier-backend.eudiw.dev/ui/presentations/"
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code=" + response_code
        )

    elif "presentation_id" in request.args:
        presentation_id = request.args.get("presentation_id")
        url = "https://dev.verifier-backend.eudiw.dev/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="

    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),400
    
    error, error_msg= validate_vp_token(response.json())

    if error == True:
        return error_msg
    
    mdoc_json = cbor2elems(response.json()["vp_token"][0] + "==")

    attributesForm={}

    for doctype in mdoc_json:
        for attribute, value in mdoc_json[doctype]:
            attributesForm.update({attribute:value})

    temp_user_id=str(uuid.uuid4())
    session[temp_user_id]= attributesForm
    session['temp_user_id'] = temp_user_id

    if session["certificate_List"]== True:
        return certificate_List(temp_user_id)
    
    user=session[temp_user_id]
    user_name=user["given_name"] + " " + user["family_name"]
    user_country = user["issuing_country"]

    check = func.check_country(user_country, session["session_id"])

    if(check != None):
        aux, check = func.user_db(user, user_name, check, session["session_id"])
        session[temp_user_id]['id'] = aux

        if(check == 1):
            attributesForm={}

            form_items={
                "Lang": "lang",
                "Role" : "select",
                "Operator Name": "string",
                "Operator Address": "string",
                "Locality": "string",
                "State or Province": "string",
                "Postal Code": "string",
                "Electronic Address": "string"
            }
            descriptions = {
                "Lang": "string",
                "Role" : "select",
                "Operator Name": "string",
                "Operator Address": "string",
                "Locality": "string",
                "State or Province": "string",
                "Postal Code": "string",
                "Electronic Address": "string"
            }

            attributesForm.update(form_items)
            
            return render_template("dynamic-form.html", role = cfgserv.roles, desc = descriptions,attributes=attributesForm,temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "user_auth")
        else:
            check = func.check_role_user(aux, session["session_id"])
            session[temp_user_id]["role"] = check
            if(cfgserv.two_operators == True):
                if(check == "tsl_op"):
                    return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
                elif(check == "tsp_op"):
                    return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
                else:
                    return ("err")
            else:
                return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)

    else:
        return ("país invalido")

@rpr.route("/user_auth", methods=["GET", "POST"])
def user_auth():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = request.form.get('Role')
    opName = request.form.get('Operator Name')
    address = request.form.get('Operator Address')
    locality = request.form.get('Locality')
    stateProvince = request.form.get('State or Province')
    postalCode = request.form.get('Postal Code')
    electronicAddress = request.form.get('Electronic Address')
    lang = request.form.get('Lang')

    op={
        "lang": lang,
        "operator_name":    opName,
        "StreetAddress"	:   address,
        "Locality"	:   locality,
        "StateOrProvince"	: stateProvince,
        "PostalCode"	: postalCode,
        "CountryName"	: user["issuing_country"],
        "EletronicAddress": electronicAddress,
        "country": user['issuing_country']
    }
    op_json = json.dumps(op)
    check = func.user_db_info(role, op_json, user['id'], session["session_id"])

    if check is None:
        return ("erro")
    else:

        check = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        session[temp_user_id]["role"] = check
        
        if(cfgserv.two_operators):
            if(check == "tsl_op"):
                return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
            elif(check == "tsp_op"):
                return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
            else:
                return ("error")
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
        
def certificate_List(temp_user_id):

    user=session[temp_user_id]

    givenName=user["given_name"]
    surname=user["family_name"]
    birth_date=user["birth_date"]
    issuing_country=user["issuing_country"]
    issuance_authority=user["issuing_authority"]

    new_user = get_hash_user_pid.User(surname, givenName, birth_date, issuing_country, issuance_authority)
    hash_pid = new_user.hash

    check = func.func_get_user_id_by_hash_pid(hash_pid, session["session_id"])

    if(check == None):
        return ("err")
    else:
        return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)

# OP
@rpr.route('/op_data_lang')
def op_lang():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    attributesForm={}

    form_items={
        "Lang": "lang",
        "Operator Name": "string",
        "Operator Address": "string",
        "Locality": "string",
        "State or Province": "string",
        "Postal Code": "string",
        "Electronic Address": "string"
    }
    descriptions = {
        "Lang": "string",
        "Operator Name": "string",
        "Operator Address": "string",
        "Locality": "string",
        "State or Province": "string",
        "Postal Code": "string",
        "Electronic Address": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", lang = cfgserv.lang, role = cfgserv.roles, desc = descriptions,attributes=attributesForm,temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "op_data_lang_db")


@rpr.route('/op_data_lang_db', methods=["GET", "POST"])
def op_lang_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    opName = request.form.get('Operator Name')
    address = request.form.get('Operator Address')
    locality = request.form.get('Locality')
    stateProvince = request.form.get('State or Province')
    postalCode = request.form.get('Postal Code')
    electronicAddress = request.form.get('Electronic Address')
    lang = request.form.get('Lang')

    op={
        "lang":lang,
        "operator_name": opName,
        "StreetAddress": address,
        "Locality": locality,
        "StateOrProvince": stateProvince,
        "PostalCode": postalCode,
        "CountryName": user["issuing_country"],
        "EletronicAddress": electronicAddress,
        "country": user['issuing_country']
    }

    db_data = func.get_data_op(user['id'], session["session_id"])
    
    op_json = json.dumps(op)
    
    combined = db_data['data']+ op_json
    
    check = func.update_db_info(combined, user['id'], session["session_id"])

    if check is None:
        return ("erro")
    else:

        check = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        session[temp_user_id]["role"] = check
        
        if(cfgserv.two_operators):
            if(check == "tsl_op"):
                return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
            elif(check == "tsp_op"):
                return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
            else:
                return ("error")
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
        




# TSL
@rpr.route('/tsl/xml')
def xml():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    user_info = func.get_user_info(user["id"], session["session_id"])

    json_objects = user_info['data'].replace('}{', '}\n{').splitlines()

    dict_list = [json.loads(json_obj) for json_obj in json_objects]

    operator_info = []
    PostalAddress_info = []
    for entry in dict_list:
        PostalAddress = {
            "lang": entry["lang"],
            "StreetAddress": entry["StreetAddress"],
            "Locality": entry["Locality"],
            "StateOrProvince": entry["StateOrProvince"],
            "PostalCode": entry["PostalCode"],
            "CountryName": entry["CountryName"]
        }
        PostalAddress_info.append(PostalAddress)

        dictFromDB_scheme_operator = {
            "lang": entry["lang"],
            "operator_name": entry["operator_name"],
            "StreetAddress": entry["StreetAddress"],
            "Locality": entry["Locality"],
            "StateOrProvince": entry["StateOrProvince"],
            "PostalCode": entry["PostalCode"],
            "CountryName": entry["CountryName"],
            "EletronicAddress": entry["EletronicAddress"],
            "country": entry["country"]
        }
        operator_info.append(dictFromDB_scheme_operator)


    tsl_info = func.tsl_info(user_info["tsl_id"], session["session_id"])
    
    dictFromDB_trusted_lists={
        "Version":  confxml.TLSIdentifier,
        "SequenceNumber":   tsl_info["SequenceNumber"],
        "TSLType":  confxml.TSLType.get("EU"),
        "SchemeName":   tsl_info["SchemeName_lang"],
        "SchemeInformationURI": tsl_info["Version"],
        "StatusDeterminationApproach":  confxml.StatusDeterminationApproach.get("EU"),
        "SchemeTypeCommunityRules": tsl_info["SchemeTypeCommunityRules_lang"],
        "PolicyOrLegalNotice":  tsl_info["PolicyOrLegalNotice_lang"],
        "pointers_to_other_tsl" :   tsl_info["pointers_to_other_tsl"].encode('utf-8'),
        "HistoricalInformationPeriod":  confxml.HistoricalInformationPeriod,
        "TSLLocation"	:   "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        #AdditionalInformation,ver

        "DistributionPoints" :  tsl_info["DistributionPoints"],
        "issue_date" :  tsl_info["issue_date"],
        "next_update":  tsl_info["next_update"],
        "status":   tsl_info["status"]
    }

    print(dictFromDB_trusted_lists)

    tsp_data = func.get_tsp_info(user_info["tsl_id"], session["session_id"])

    json_objects = tsp_data['data'].replace('}{', '}\n{').splitlines()

    dict_list = [json.loads(json_obj) for json_obj in json_objects]

    tsp_info = []
    for entry in dict_list:
        dictFromDB_trust_service_providers = {
            "lang": entry["lang"],
            "name": entry["name"],
            "trade_name": entry["trade_name"],
            "StreetAddress": entry["StreetAddress"],
            "Locality": entry["Locality"],
            "StateOrProvince": entry["StateOrProvince"],
            "PostalCode": entry["PostalCode"],
            "CountryName": entry["CountryName"],
            "EletronicAddress": entry["EletronicAddress"],
            "TSPInformationURI": entry["TSPInformationURI"],
            "country": entry["name"]
        }
        tsp_info.append(dictFromDB_trust_service_providers)

    service_data = func.get_service_info(tsp_data["tsp_id"], session["session_id"])

    qualifiers = cfgserv.qualifiers.get(service_data["qualifier"])

    json_objects = service_data['data'].replace('}{', '}\n{').splitlines()

    dict_list = [json.loads(json_obj) for json_obj in json_objects]

    service_info = []
    for entry in dict_list:
        dictFromDB_trust_services={
            "lang": entry["lang"],
            "service_type": service_data['service_type'],
            "service_name": entry["ServiceName"],
            "digital_identity" :    service_data["digital_identity"],
            "status" :  service_data["status"],
            "status_start_date":    service_data["status_start_date"],
            "SchemeServiceDefinitionURI":   entry["SchemeServiceDefinitionURI"]
        }
        service_info.append(dictFromDB_trust_services)

    file = xml_gen(PostalAddress_info, operator_info, dictFromDB_trusted_lists, tsp_info, service_info, qualifiers)
    
    return render_template("download_tsl.html", dictFromDB_trusted_lists = dictFromDB_trusted_lists, dictFromDB_trust_services = service_info, file_data = file, temp_user_id = temp_user_id)
    
@rpr.route('/download', methods=["GET", "POST"])
def download_tsl():

    encoded_file = request.form.get("file_data")

    file_data = base64.b64decode(encoded_file)

    return send_file(
        io.BytesIO(file_data),
        download_name="generated_file.xml",
        as_attachment=True,
        mimetype='application/xml'
    )

@rpr.route('/operator_menu_tsl', methods=["GET"])
def operator_menu_tsl():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    if(cfgserv.two_operators):
        return render_template("operator_menu_tsl.html", user=user['given_name'], temp_user_id=temp_user_id)
    else:
        return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)

@rpr.route('/tsl/view')
def view_tsl():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    tsl = func.get_tsl_info(user["id"], session["session_id"])

    if tsl is None:
        return render_template("view.html", temp_user_id = temp_user_id, tsl = None, message = "User dont have a tsl created")
    else:
        return render_template("view.html", temp_user_id = temp_user_id, tsl = tsl)

@rpr.route('/tsl/create')
def create_tsl():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    attributesForm={}

    form_items={
        "Version": "int",
        "TSL Type" : "string",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Territory": "string",
        "Scheme Type Community Rules": "rules",
        "Policy Or Legal Notice": "string",
        "Pointers to other TSL": "string",
        "Distribution Points": "string",
        "Issue_date": "full-date",
        "Next Update": "full-date",
        "Status": "string",
        "Additional Information": "string"
    }
    descriptions = {
        "Version": "int",
        "TSL Type" : "string",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Territory": "string",
        "Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        "Pointers to other TSL": "string",
        "Distribution Points": "string",
        "Issue_date": "full-date",
        "Next Update": "full-date",
        "Status": "string",
        "Additional Information": "string"
    }

    attributesForm.update(form_items)
    rules = cfgserv.SchemeTypeCommunityRules

    # for items in rules:
    #     if 'Scheme Territory' in items:
    #         rules[items] = rules[items] + user['issuing_country']
            
    return render_template("form.html", rules = rules, lang = cfgserv.lang, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsl/create/db")


@rpr.route('/tsl/create/db', methods=["GET", "POST"])
def create_tsl_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    Version = request.form.get('Version')
    Sequence_number = 1
    TSLType = request.form.get('TSL Type')
    SchemeName_lang = request.form.get('Scheme Name')
    Uri_lang = request.form.get('Uri')
    print(request.form)
    options = request.form.getlist('rules')
    SchemeTypeCommunityRules_lang = ", ".join(options)

    schemeTerritory = request.form.get('Scheme Territory')
    PolicyOrLegalNotice_lang = request.form.get('Policy Or Legal Notice')
    PointerstootherTSL = request.form.get('Pointers to other TSL')
    DistributionPoints = request.form.get('Distribution Points')
    Issue_date = request.form.get('Issue_date')
    NextUpdate = request.form.get('Next Update')
    Status = request.form.get('Status')
    AdditionalInformation = request.form.get('Additional Information')
   

    check = func.check_country(user['issuing_country'], session["session_id"])
    check = func.tsl_db_info(Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang,
                             PolicyOrLegalNotice_lang, PointerstootherTSL, 
                             DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, schemeTerritory, check, session["session_id"])
    
    
    if check is None:
        return ("err")
    else:
        check = func.update_user_tsl(user['id'], check, session["session_id"])
        if check is None:
            return (check)
        else:
            if(cfgserv.two_operators):
                return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
            else:
                return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
            
            

@rpr.route('/tsl/update')
def update_tsl():
    return "Atualizar TSL Existente"

@rpr.route('/tsl/sign')
def sign_tsl():
    return "Assinar Digitalmente a TSL"

# TSP
@rpr.route('/tsp/create')
def create_tsp():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "StreetAddress" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "country": "string"
    }
    descriptions = {
        "Lang": "string",
        "Name": "string",
        "Trade Name": "string",
        "StreetAddress" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "country": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", lang = cfgserv.lang, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsp/create/db")


@rpr.route('/tsp/create/db', methods=["GET", "POST"])
def create_tsp_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    name = request.form.get('Name')
    trade_name = request.form.get('Trade Name')
    StreetAddress = request.form.get('StreetAddress')
    Locality= request.form.get('Locality')
    StateOrProvince= request.form.get('State Or Province')
    PostalCode= request.form.get('Postal Code')
    CountryName= request.form.get('Country Name')
    EletronicAddress= request.form.get('Eletronic Address')
    TSPInformationURI= request.form.get('TSP Information URI')
    country= request.form.get('country')
    lang = request.form.get('Lang')

    tsp = {
        "lang" :    lang,
        "name" :    name,
        "trade_name" :  trade_name,
        "StreetAddress"	:   StreetAddress,
        "Locality"	:   Locality,
        "StateOrProvince"	:   StateOrProvince,
        "PostalCode"	:   PostalCode,
        "CountryName"	:   CountryName,
        "EletronicAddress": EletronicAddress,
        "TSPInformationURI":    TSPInformationURI,
        "country":  country
    }
    
    tsp_json = json.dumps(tsp)

    check = func.tsp_db_info(session[temp_user_id]["id"], tsp_json, session["session_id"])

    if check is None:
        return "err"
    else:
        if(cfgserv.two_operators):
            return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
        

@rpr.route('/tsp/tsp_data_lang')
def tsp_lang():
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "StreetAddress" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "country": "string"
    }
    descriptions = {
        "Lang": "string",
        "Name": "string",
        "Trade Name": "string",
        "StreetAddress" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "country": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", lang = cfgserv.lang, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsp/tsp_db_data_lang")


@rpr.route('/tsp/tsp_db_data_lang', methods=["GET", "POST"])
def tsp_db_lang():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    name = request.form.get('Name')
    trade_name = request.form.get('Trade Name')
    StreetAddress = request.form.get('StreetAddress')
    Locality= request.form.get('Locality')
    StateOrProvince= request.form.get('State Or Province')
    PostalCode= request.form.get('Postal Code')
    CountryName= request.form.get('Country Name')
    EletronicAddress= request.form.get('Eletronic Address')
    TSPInformationURI= request.form.get('TSP Information URI')
    country= request.form.get('country')
    lang = request.form.get('Lang')

    tsp = {
        "lang" :    lang,
        "name" :    name,
        "trade_name" :  trade_name,
        "StreetAddress"	:   StreetAddress,
        "Locality"	:   Locality,
        "StateOrProvince"	:   StateOrProvince,
        "PostalCode"	:   PostalCode,
        "CountryName"	:   CountryName,
        "EletronicAddress": EletronicAddress,
        "TSPInformationURI":    TSPInformationURI,
        "country":  country
    }
    
    db_data, tsl_id = func.get_data_tsp(user['id'], session["session_id"])
    
    tsp_json = json.dumps(tsp)
    combined = db_data+ tsp_json
    
    check = func.tsp_db_lang(session[temp_user_id]["id"], tsl_id, combined, session["session_id"])

    if check is None:
        return "err"
    else:
        if(cfgserv.two_operators):
            return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
        
       
# Service
@rpr.route('/service/create')
def create_service():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Service Type": "select_type",
        "Service Name": "select_name",
        "Qualifier": "select",
        "Digital Identity" : "string",
        "Status": "string",
        "Status Start Date": "full-date",
        "Uri": "string"
    }
    descriptions = {
        "Lang": "string",
        "Service Type": "Type of service provided",
        "Service Name": "Provide the service name",
        "Qualifier": "Select applicable qualifiers",
        "Digital Identity": "Specify the digital identity",
        "Status": "Service status",
        "Status Start Date": "Start date of the current status",
        "Uri": "Service URI"
    }

    attributesForm.update(form_items)
    
    return render_template("form_service.html", lang = cfgserv.lang, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, 
                           data = cfgserv.qualifiers, redirect_url= cfgserv.service_url + "service/create/db", qualified = cfgserv.qualified,
                           non_qualified = cfgserv.non_qualified, national = cfgserv.national, serv_cat = cfgserv.service_category)


@rpr.route('/service/create/db', methods=["GET", "POST"])
def service_tsp_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    service_type = request.form.get('category')
    service_name = request.form.get('option')
    qualifier = request.form.get('Qualifier')
    digital_identity = request.form.get('Digital Identity')
    status = request.form.get('Status')
    status_start_date = request.form.get('Status Start Date')
    uri = request.form.get('Uri')
    lang = request.form.get('Lang')

    service = {
        "lang":    lang, 
        "ServiceName" :    service_name,
        "SchemeServiceDefinitionURI" :  uri
    }

    service_json = json.dumps(service)

    check = func.service_db_info(session[temp_user_id]["id"], service_json, digital_identity, service_type, status, status_start_date, qualifier, session["session_id"])

    if check is None:
        return (check)
    else:
        if(cfgserv.two_operators):
            return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
       

@rpr.route('/service/service_lang')
def service_lang():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Service Name": "string",
        "Uri": "string"
    }
    descriptions = {
        "Lang": "string",
        "Service Name": "Provide the service name",
        "Uri": "Service URI"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", lang = cfgserv.lang, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, 
                           data = cfgserv.qualifiers, redirect_url= cfgserv.service_url + "service/service_lang_db")


@rpr.route('/service/service_lang_db', methods=["GET", "POST"])
def service_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    service_name = request.form.get('Service Name')
    uri = request.form.get('Uri')
    lang = request.form.get('Lang')

    service = {
        "lang":    lang, 
        "ServiceName" :    service_name,
        "SchemeServiceDefinitionURI" :  uri
    }

    db_data, tsp_id = func.get_data_service(user['id'], session["session_id"])
    
    service_json = json.dumps(service)

    combined = db_data['data'] + service_json

    check = func.service_db_lang(session[temp_user_id]["id"], tsp_id, combined, session["session_id"])

    if check is None:
        return ("err")
    else:
        if(cfgserv.two_operators):
            return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
        else:
            return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
       



@rpr.route('/logout')
def logout():
    session.clear()
    
    return redirect(url_for('RPR.initial_page'))