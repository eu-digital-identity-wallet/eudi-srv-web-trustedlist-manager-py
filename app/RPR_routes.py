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
from app_config.EJBCA_config import EJBCA_Config as ejbca
import app.EJBCA_and_DB_func as func
from app_config.Crypto_Info import Crypto_Info as crypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


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

    oid4vp_requests.update({session["session_id"]:{"response": response_same_device, "expires":datetime.now() + timedelta(minutes=cfgserv.deffered_expiry)}})


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
                "Role" : "select",
                "Operator Address": "string",
                "Locality": "string",
                "State or Province": "string",
                "Postal Code": "string",
                "Electronic Address": "string",
            }
            descriptions = {
                "Role": "select",
                "Operator Address": "string",
                "Locality": "string",
                "State or Province": "string",
                "Postal Code": "string",
                "Electronic Address": "string",
            }

            attributesForm.update(form_items)
            
            return render_template("dynamic-form.html", role = cfgserv.roles, desc = descriptions,attributes=attributesForm,temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "user_auth")
        else:

            check = func.check_role_user(aux, session["session_id"])
            session[temp_user_id]["role"] = check

            if(check == "tsl_op"):
                return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
            elif(check == "tsp_op"):
                return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
    else:
        return ("país invalido")

@rpr.route("/user_auth", methods=["GET", "POST"])
def user_auth():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = request.form.get('Role')
    address = request.form.get('Operator Address')
    locality = request.form.get('Locality')
    stateProvince = request.form.get('State or Province')
    postalCode = request.form.get('Postal Code')
    electronicAddress = request.form.get('Electronic Address')

    check = func.user_db_info(role, address, locality, stateProvince, postalCode, electronicAddress, user['id'], session["session_id"])

    if(check == None):
        return ("erro")
    else:

        check = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        session[temp_user_id]["role"] = check

        if(check == "tsl_op"):
            return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
        elif(check == "tsp_op"):
            return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
        
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
        

# TSL
@rpr.route('/tsl/view')
def view_tsl():
    return "Visualizar TSL Atual"

@rpr.route('/tsl/create')
def create_tsl():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Version": "int",
        "Sequence_number": "int",
        "TSL Type" : "string",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        "Pointers to other TSL": "string",
        "Distribution Points": "string",
        "Issue_date": "full-date",
        "Next Update": "full-date",
        "Status": "string",
        "Signature": "binary"
    }
    descriptions = {
        "Version": "int",
        "Sequence_number": "int",
        "TSL Type" : "string",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        "Pointers to other TSL": "string",
        "Distribution Points": "string",
        "Issue_date": "full-date",
        "Next Update": "full-date",
        "Status": "string",
        "Signature": "binary"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsl/create/bd")


@rpr.route('/tsl/create/bd', methods=["GET", "POST"])
def create_tsl_bd():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    Version = request.form.get('Version')
    Sequence_number = request.form.get('Sequence_number')
    TSLType = request.form.get('TSL Type')
    SchemeName = request.form.get('Scheme Name')
    Uri = request.form.get('Uri')
    SchemeTypeCommunityRules = request.form.get('Scheme Type Community Rules')
    PolicyOrLegalNotice = request.form.get('Policy Or Legal Notice')
    PointerstootherTSL = request.form.get('Pointers to other TSL')
    DistributionPoints = request.form.get('Distribution Points')
    Issue_date = request.form.get('Issue_date')
    NextUpdate = request.form.get('Next Update')
    Status = request.form.get('Status')
    Signature = request.form.get('Signature')

    check = func.check_country(user['issuing_country'], session["session_id"])
    check = func.tsl_db_info(Version, Sequence_number, TSLType, SchemeName, Uri, SchemeTypeCommunityRules, PolicyOrLegalNotice, 
                        PointerstootherTSL, DistributionPoints, Issue_date, NextUpdate, Status, Signature, check, session["session_id"])

    if(check == None):
        return (check)
    else:
        check = func.update_user_tsl(user['id'], check, session["session_id"])
        if(check == None):
            return (check)
        else:
            return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)
       
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
        "Name": "string",
        "Trade Name": "string",
        "Address" : "string",
        "Contact Email": "string"
    }
    descriptions = {
        "Name": "string",
        "Trade Name": "string",
        "Address" : "string",
        "Contact Email": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsp/create/bd")


@rpr.route('/tsp/create/bd', methods=["GET", "POST"])
def create_tsp_bd():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    name = request.form.get('Name')
    trade_name = request.form.get('Trade Name')
    address = request.form.get('Address')
    contact_email= request.form.get('Contact Email')

    check = func.tsp_db_info(session[temp_user_id]["id"], name, trade_name, address, contact_email, session["session_id"])

    if check is None:
        return (check)
    else:
        return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)
       