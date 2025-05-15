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
This rpr_routes.py file is the blueprint of the Web Trusted List Manager service.
"""

from app import logger
import base64
import binascii
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import io
import json
import os
import re
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
from xml_gen.xmlGen import xml_gen_xml, xml_gen_lotl_xml, xml_validator
from xml_gen.xmlGen_List import xml_gen_xml_lotl
from dateutil.relativedelta import relativedelta
import ast

rpr = Blueprint("RPR", __name__, url_prefix="/")

rpr.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

@rpr.route('/', methods=['GET','POST'])
def initial_page():

    return render_template('initial_page.html', redirect_url= cfgserv.service_url, pid_auth = cfgserv.service_url + "authentication", certificateList=cfgserv.service_url + "authentication_List")

@rpr.route('/menu', methods=['GET','POST'])
def menu():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
                    
    return render_template("operator_menu.html", user = user['given_name'], temp_user_id = temp_user_id)
    
@rpr.route('/menu_tsp', methods=['GET','POST'])
def menu_tsp():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    return render_template("operator_menu_tsp.html", user = user['given_name'], temp_user_id = temp_user_id)

@rpr.route('/menu_tsl', methods=['GET','POST'])
def menu_tsl():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    return render_template("operator_menu_tsl.html", user = user['given_name'], temp_user_id = temp_user_id)

@rpr.route('/menu_lotl', methods=['GET','POST'])
def menu_lotl():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    return render_template("operator_menu_lotl.html", user = user['given_name'], temp_user_id = temp_user_id)

@rpr.route("/authentication", methods=["GET","POST"])
def authentication():

    url = "https://" + cfgserv.url_verifier +"/ui/presentations"
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
        "eudi-openid4vp://" + cfgserv.url_verifier + "?client_id="
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
        "eudi-openid4vp://" + cfgserv.url_verifier + "?client_id="
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
        presentation_id=response["transaction_id"],
        redirect_url= cfgserv.service_url
    )
@rpr.route("/authentication_List", methods=["GET","POST"])
def authentication_List():

    url = "https://" + cfgserv.url_verifier +"/ui/presentations"
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
        "eudi-openid4vp://" + cfgserv.url_verifier + "?client_id="
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
        "eudi-openid4vp://" + cfgserv.url_verifier + "?client_id="
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
        presentation_id=response["transaction_id"],
        redirect_url= cfgserv.service_url
    )

@rpr.route("/pid_authorization")
def pid_authorization_get():

    presentation_id= request.args.get("presentation_id")

    url = "https://" + cfgserv.url_verifier+ "/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
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
        presentation_id = oid4vp_requests[request.args.get("session_id")]["response"]["transaction_id"]
        session["session_id"]=request.args.get("session_id")
        if oid4vp_requests[request.args.get("session_id")]["certificate_List"] !=None:
            session["certificate_List"]=True
        url = (
            "https://" + cfgserv.url_verifier+ "/ui/presentations/"
            + presentation_id
            + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
            + "&response_code=" + response_code
        )

    elif "presentation_id" in request.args:
        presentation_id = request.args.get("presentation_id")
        url = "https://" + cfgserv.url_verifier+ "/ui/presentations/" + presentation_id + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="

    headers = {
    'Content-Type': 'application/json',
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg= str(response.status_code)
        return jsonify({"error": error_msg}),400

    error, error_msg, pos= validate_vp_token(response.json())

    if error == True:
        return error_msg
    
    mdoc_json = cbor2elems(response.json()["vp_token"][0] + "==", pos)

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
                "Operator Name": "op_name",
                "Electronic Address": "string",
                "Street Address" : "string",
                "Locality": "string",
                "State Or Province": "string",
                "Postal Code": "string",
                "Country Name": "country"
            }
            descriptions = {
                "Lang": "string",
                "Role" : "select",
                "Operator Name": "op_name",
                "Electronic Address": "string",
                "Street Address" : "string",
                "Locality": "string",
                "State Or Province": "string",
                "Postal Code": "string",
                "Country Name": "country"
            }

            attributesForm.update(form_items)
            
            return render_template("form_create.html", user_name = user_name, h3 = "Operator information form", countries=cfgserv.eu_countries, title="Trusted List", data = cfgserv.roles, status = cfgserv.statusDetermination,  TSLType= cfgserv.TSLType, lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id,  redirect_url = cfgserv.service_url + "user_auth")
        else:
            check = func.check_role_user(aux, session["session_id"])
            if(cfgserv.two_operators == True):
                if(check == "tsl_op"):
                    return redirect(url_for('RPR.menu_tsl'))
                elif(check == "tsp_op"):
                    return redirect(url_for('RPR.menu_tsp'))
                elif(check == "lotl_op"):
                    return redirect(url_for('RPR.menu_lotl'))
                else:
                    return ("err")
            else:
                if(check == "lotl_op"):
                    return redirect(url_for('RPR.menu_lotl'))
                return redirect(url_for('RPR.menu'))
    else:
        return ("país invalido")

@rpr.route("/user_auth", methods=["GET", "POST"])
def user_auth():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = request.form.get('Role')
    opName = request.form.get('operator_name')
    address = request.form.get('Street Address')
    locality = request.form.get('Locality')
    stateProvince = request.form.get('State Or Province')
    postalCode = request.form.get('Postal Code')
    electronicAddress = request.form.get('Electronic Address')
    Country = request.form.get('Country Name')
    lang = request.form.get('Lang')

    operator_name = '[{"lang":"' + lang + '", "text":"'+ opName + '"}]'
    electronicAddress = '[{"lang":"' + lang + '", "URI":"'+ electronicAddress + '"}]'
    
    PostalAddress = '[{"lang":"' + lang + '", "StreetAddress":"'+ address + '", "Locality":"'+ locality + '", "StateOrProvince":"'+ stateProvince + '", "PostalCode":"'+ postalCode + '", "CountryName":"'+ Country + '"}]'
    
    check = func.user_db_info(role, operator_name, PostalAddress, electronicAddress, user['id'], session["session_id"])

    if check is None:
        return ("erro")
    else:
        check = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(cfgserv.two_operators == True):
            if(check == "tsl_op"):
                return redirect(url_for('RPR.menu_tsl'))
            elif(check == "tsp_op"):
                return redirect(url_for('RPR.menu_tsp'))
            elif(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            else:
                return ("err")
        else:
            if(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            return redirect(url_for('RPR.menu'))
        
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
        "Electronic Address": "string",
        "Street Address" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country"
    }
    descriptions = {
        "Lang": "string",
        "Operator Name": "string",
        "Electronic Address": "string",
        "Street Address" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", countries=cfgserv.eu_countries, title="Scheme Operator", lang = cfgserv.eu_languages, role = cfgserv.roles, desc = descriptions, attributes = attributesForm, 
                           temp_user_id = temp_user_id, redirect_url = cfgserv.service_url + "op_data_lang_db")


@rpr.route('/op_data_lang_db', methods=["GET", "POST"])
def op_lang_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    opName = request.form.get('Operator Name')
    address = request.form.get('Street Address')
    locality = request.form.get('Locality')
    stateProvince = request.form.get('State Or Province')
    postalCode = request.form.get('Postal Code')
    electronicAddress = request.form.get('Electronic Address')
    Country = request.form.get('Country Name')
    lang = request.form.get('Lang')

    
    db_data = func.get_data_op(user['id'], session["session_id"])

    current_data_operator_name = None
    current_data_postal_address = None
    current_data_electronicAddress = None

    if opName:
        operator_name = {"lang": lang, "text": opName}
        current_data_operator_name = json.loads(db_data.get('operator_name', '[]'))
        current_data_operator_name.append(operator_name)
        current_data_operator_name = json.dumps(current_data_operator_name)

    if electronicAddress:
        electronic_address_data = {"lang": lang, "URI": electronicAddress}
        current_data_electronicAddress = json.loads(db_data.get('EletronicAddress', '[]'))
        current_data_electronicAddress.append(electronic_address_data)
        current_data_electronicAddress = json.dumps(current_data_electronicAddress)

    if all([address, locality, stateProvince, postalCode, Country]):
        postal_address = {
            "lang": lang,
            "StreetAddress": address,
            "Locality": locality,
            "StateOrProvince": stateProvince,
            "PostalCode": postalCode,
            "CountryName": Country
        }
        current_data_postal_address = json.loads(db_data.get('postal_address', '[]'))
        current_data_postal_address.append(postal_address)
        current_data_postal_address = json.dumps(current_data_postal_address)

    check = func.update_db_info(
        current_data_operator_name, 
        current_data_postal_address, 
        current_data_electronicAddress, 
        user['id'], 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(cfgserv.two_operators == True):
            if(role == "tsl_op"):
                return redirect(url_for('RPR.menu_tsl'))
            elif(role == "tsp_op"):
                return redirect(url_for('RPR.menu_tsp'))
            elif(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            else:
                return ("err")
        else:
            if(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            return redirect(url_for('RPR.menu'))

@rpr.route('/op_edit')
def op_edit():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    db_data = func.get_data_op_edit(user['id'], session["session_id"])

    for key in db_data: 
        db_data[key] = json.loads(db_data[key])
    
    return render_template("dynamic-form_edit_TLS.html", h3 = "Operator Information", title = "Scheme Operator", lang = cfgserv.lang, role = cfgserv.roles, data_edit = db_data, Langs=cfgserv.eu_languages,Countries=cfgserv.eu_countries, temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "op_edit_db")

@rpr.route('/op_edit_db', methods=["GET", "POST"])
def op_edit_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    form = dict(request.form)
    form.pop("proceed")
    grouped = defaultdict(list)

    for key, value in form.items():
        match = re.match(r"(lang|text|URI)_(.*?).(\d+)", key)
        match2=re.match(r"(postal_address)_(.*?).(\d+)",key)
        if match:
            attr, prefix, index = match.groups()
            index = int(index)
            while len(grouped[prefix]) <= index:
                grouped[prefix].append({})
            grouped[prefix][index][attr] = value
        elif match2:
            attr, prefix, index = match2.groups()
            index = int(index)
            while len(grouped[attr]) <= index:
                grouped[attr].append({})
            grouped[attr][index][prefix] = value

        elif "DistributionPoints" in key:
                key_dict=key.split(".")
                grouped[key_dict[0]].append(value)
                
        else:
            grouped[key] = value
    
    check = func.edit_op_db_info(
        grouped, 
        user['id'], 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(cfgserv.two_operators == True):
            if(role == "tsl_op"):
                return redirect(url_for('RPR.menu_tsl'))
            elif(role == "tsp_op"):
                return redirect(url_for('RPR.menu_tsp'))
            elif(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            else:
                return ("err")
        else:
            if(check == "lotl_op"):
                return redirect(url_for('RPR.menu_lotl'))
            return redirect(url_for('RPR.menu'))


# TSL
@rpr.route('/tsl/XMLgen')
def xml_gen():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsl_dict = func.get_tsl_xml(user["id"], session["session_id"])
    data = []

    for item in tsl_dict:

        new_item = {
            "id": item["tsl_id"],
            "name": item["SchemeName_lang"]
        }
        
        data.append(new_item)

    return render_template("form_genXML.html", data=data, temp_user_id = temp_user_id, redirect_url = "/tsl/xml")

@rpr.route('/tsl/xml', methods=["GET", "POST"])
def xml():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsl_id = request.args.get("id")

    check = func.check_tsl(tsl_id, session["session_id"])

    if check == "tsp":
        flash("This TSL doesn't have at least one TSP associated.", "danger")
        return redirect('/tsl/list')
    elif check == "service":
        flash("This TSL doesn't have at least one Service associated to an TSP.", "warning")
        return redirect('/tsl/list')
    
    user_info = func.get_user_info(user["id"], session["session_id"])

    tsl_info = func.tsl_info(tsl_id, session["session_id"])

    lang_based_fields = [
        "SchemeName_lang",
        "Uri_lang",
        "SchemeTypeCommunityRules_lang",
        "PolicyOrLegalNotice_lang"
    ]

    for key in lang_based_fields:
        try:
            tsl_info[key] = json.loads(tsl_info[key]) if tsl_info[key] else []
        except json.JSONDecodeError:
            extra = {'code': session["session_id"]} 
            logger.error(f"Error decoding : {key}: {tsl_info[key]}", extra=extra)
            print(f"Error decoding {key}: {tsl_info[key]}")
            tsl_info[key] = []

    try:
        tsl_info["DistributionPoints"] = json.loads(tsl_info["DistributionPoints"]) if tsl_info["DistributionPoints"] else []
        if not isinstance(tsl_info["DistributionPoints"], list):
            raise ValueError("DistributionPoints não é uma lista válida!")
    except (json.JSONDecodeError, ValueError):
        extra = {'code': session["session_id"]} 
        logger.error(f"Error decoding DistributionPoints: {tsl_info['DistributionPoints']}", extra=extra)
        print(f"Error decoding DistributionPoints: {tsl_info['DistributionPoints']}")
        tsl_info["DistributionPoints"] = []

    
    dictFromDB_trusted_lists={
        "Version":  confxml.TLSVersionIdentifier,
        "SequenceNumber":   tsl_info["SequenceNumber"],
        #"TSLType":  confxml.TSLType.get("EU"),
        "SchemeName":   tsl_info["SchemeName_lang"],
        "SchemeInformationURI": tsl_info["Uri_lang"],
        #"StatusDeterminationApproach":  confxml.StatusDeterminationApproach.get("EU"),
        #"SchemeTypeCommunityRules": tsl_info["SchemeTypeCommunityRules_lang"],
        "PolicyOrLegalNotice":  tsl_info["PolicyOrLegalNotice_lang"],
        #"pointers_to_other_tsl" :   tsl_info["pointers_to_other_tsl"].encode('utf-8'),
        "HistoricalInformationPeriod":  confxml.HistoricalInformationPeriod,
        "TSLLocation"	:   "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
        "schemeTerritory": tsl_info["schemeTerritory"],
        #AdditionalInformation,ver

        #"DistributionPoints" :  tsl_info["DistributionPoints"],
        "issue_date" :  tsl_info["issue_date"],
        "next_update":  tsl_info["next_update"],
        "status":   tsl_info["status"]
    }
    
    tsp_data = func.get_tsp_info_xml(tsl_id, session["session_id"])

    service_data = []

    for item in tsp_data:
        tsp_id = item["tsp_id"]
        
        service_info = func.get_service_info_xml(tsp_id, session["session_id"])
    
        service_data.append(service_info)

    # for service_list in service_data:
    #     for service in service_list:
    #         service['qualifier'] = cfgserv.qualifiers.get(service["qualifier"])

    file, thumbprint, xml_hash_before_sign = xml_gen_xml(user_info, dictFromDB_trusted_lists, tsp_data, service_data, tsl_info["tsl_id"], session["session_id"])
    
    if(cfgserv.two_operators):
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(role == "tsl_op"):
            menu= cfgserv.service_url + "menu_tsl"
            return render_template("download_tsl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, dictFromDB_trusted_lists = dictFromDB_trusted_lists, file_data = file, temp_user_id = temp_user_id)
        elif(role == "tsp_op"):
            menu= cfgserv.service_url + "menu_tsp"
            return render_template("download_tsl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, dictFromDB_trusted_lists = dictFromDB_trusted_lists, file_data = file, temp_user_id = temp_user_id)
        else:
            return ("error")
    else:
        menu= cfgserv.service_url + "menu"

    return render_template("download_tsl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, dictFromDB_trusted_lists = dictFromDB_trusted_lists, file_data = file, temp_user_id = temp_user_id, url= cfgserv.service_url)

    
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

@rpr.route('/validate_xml', methods=["GET", "POST"])
def validate_xml():

    encoded_file = request.args.get("file")
    file_data = base64.b64decode(encoded_file)

    code,msg= xml_validator(file_data)
    if code == 200:
        
        return jsonify({"message": msg}),code
    
    else:
        return jsonify({"error":msg}),code
    

    return msg

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

@rpr.route('/tsl/list')
def list_tsl():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    tsl_dict = func.get_tsl_info(user["id"], session["session_id"])
    
    header_table=[ "Version","Sequence Number","TSL Type","Scheme Name","Scheme Territory","Issue Date","Next Update"]
    if(tsl_dict == "err"):
        data={}
    else:

        data={}

        for tsl in tsl_dict:
            data_temp={
                tsl["tsl_id"]:{
                    "Version":tsl["Version"],
                    "Sequence Number":tsl["SequenceNumber"],
                    "TSL Type":tsl["TSLType"],
                    "Scheme Name":tsl["SchemeName_lang"],
                    "Scheme Territory":tsl["schemeTerritory"],
                    "Issue Date":tsl["issue_date"],
                    "Next Update":tsl["next_update"]
                }
            }
            data.update(data_temp)
    
    tsp_dict = func.get_tsp_update(user["id"], session["session_id"])
    
    list = []
    if(data != {}):
        if(tsp_dict != "err"):

            for item in tsp_dict:
                name = json.loads(item["name"])
                
                name_txt = name[0]["text"] if name else "No Name"
                if(item["tsl_id"] != None):
                    tsl_name = func.get_tsl_name(item["tsl_id"], session["session_id"])
                    aux_name = json.loads(tsl_name["SchemeName_lang"])
                    tsl_name = aux_name[0]["text"] if aux_name else "No Name"
                    
                    new_item = {
                        "id": item["tsp_id"],
                        "name": name_txt,
                        "associated_id": item["tsl_id"],
                        "ass_name": tsl_name
                    }
                else:
                    new_item = {
                        "id": item["tsp_id"],
                        "name": name_txt,
                        "associated_id": item["tsl_id"],
                        "ass_name": ""
                    }
                
                list.append(new_item)
    
    if(cfgserv.two_operators):
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(role == "tsl_op"):
            menu= cfgserv.service_url + "menu_tsl"
            return render_template("CertificateList.html", h1 = "Trusted Service Lists", menu = menu, data=data, title="Trusted Lists", list= list, header_table=header_table, url=cfgserv.service_url +"tsl", temp_user_id = temp_user_id)
        elif(role == "tsp_op"):
            menu= cfgserv.service_url + "menu_tsp"
            return render_template("CertificateList.html", h1 = "Trusted Service Lists", menu = menu, data=data, title="Trusted Lists", list= list, header_table=header_table, url=cfgserv.service_url +"tsl", temp_user_id = temp_user_id)
        else:
            return ("error")
    else:
        menu= cfgserv.service_url + "menu"
        return render_template("CertificateList.html", h1 = "Trusted Service Lists", menu = menu, data=data, title="Trusted Lists", list= list, header_table=header_table, url=cfgserv.service_url +"tsl", temp_user_id = temp_user_id)

    
@rpr.route('/tsl/create')
def create_tsl():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        #"TSL Type" : "TSLType",
        "Scheme Name": "string", 
        "Scheme Information URI": "string",
        "Scheme Territory": "country",
        #"Scheme Type Community Rules": "rules",
        "Policy Or Legal Notice": "string",
        #"Pointers to other TSL": "string",
        #"Distribution Points": "string",
        #"Status determination approach": "StatusDetermination",
        "Additional Information": "string"
    }
    descriptions = {
        "Lang": "lang",
        #"TSL Type" : "string",
        "Scheme Name": "string", 
        "Scheme Information URI": "string",
        "Scheme Territory": "country",
        #"Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        #"Pointers to other TSL": "string",
        #"Distribution Points": "string",
        #"Status": "string",
        "Additional Information": "string"
    }

    attributesForm.update(form_items)
    rules = cfgserv.SchemeTypeCommunityRules

    # for items in rules:
    #     if 'Scheme Territory' in items:
    #         rules[items] = rules[items] + user['issuing_country']
            
    return render_template("form_create.html", h3 = "Trusted List information form", countries=cfgserv.eu_countries, title="Trusted List", rules = rules, status = cfgserv.statusDetermination,  TSLType= cfgserv.TSLType, lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsl/create/db")

@rpr.route('/tsl/create/db', methods=["GET", "POST"])
def create_tsl_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    lang = request.form.get('Lang') 
    Version = confxml.TLSVersionIdentifier
    Sequence_number = 1
    #TSLType = request.form.get('TSL Type')
    SchemeName_lang = request.form.get('Scheme Name')
    Uri_lang = request.form.get('Scheme Information URI')
    
    #options = request.form.getlist('rules')
 
    schemeTerritory = request.form.get('Scheme Territory')
    PolicyOrLegalNotice_lang = request.form.get('Policy Or Legal Notice')
    #PointerstootherTSL = request.form.get('Pointers to other TSL')
    #DistributionPoints = request.form.get('Distribution Points')
    Issue_date = datetime.now()
    NextUpdate = Issue_date + timedelta(days=6*30)
    #Status = request.form.get('Status determination approach')
    AdditionalInformation = request.form.get('Additional Information')

    # if TSLType == "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist":
    #     TSLType="http://uri.etsi.org/TrstSvc/TrustedList/TSLType/"+ schemeTerritory + "list"
    
    # if  "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/" in options:
    #    i= options.index("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/")
    #    options[i]= "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/" + schemeTerritory

    # SchemeTypeCommunityRules_lang = ", ".join(options)

    SchemeName_lang = '[{"lang":"' + lang + '", "text":"'+ SchemeName_lang + '"}]'
    Uri_lang = '[{"lang":"' + lang + '", "URI":"'+ Uri_lang + '"}]'
    #SchemeTypeCommunityRules_lang = '[{"lang":"' + lang + '", "URI":"'+ SchemeTypeCommunityRules_lang + '"}]'
    PolicyOrLegalNotice_lang = '[{"lang":"' + lang + '", "text":"'+ PolicyOrLegalNotice_lang + '"}]'
    #DistributionPoints = '["'+ DistributionPoints + '"]'

    lotl = 0

    check = func.check_country(user['issuing_country'], session["session_id"])
    check = func.tsl_db_info(user['id'], Version, Sequence_number, SchemeName_lang, Uri_lang,
                             PolicyOrLegalNotice_lang, Issue_date, NextUpdate, 
                             AdditionalInformation, schemeTerritory, lotl, check, session["session_id"])
    
    if check is None:
        return ("err")
    else:   
        return redirect('/tsl/list')

@rpr.route('/tsl/edit', methods=["GET", "POST"])
def tsl_edit():
    
    if not request.args.get("id"):
        return ""
    
    tsl_id = request.args.get("id")

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    db_data = func.get_data_tsl_edit(tsl_id, session["session_id"])

    for key in db_data:
        if db_data[key]: 
            try:
                db_data[key] = json.loads(db_data[key])
            except json.JSONDecodeError as e:
                extra = {'code': session["session_id"]} 
                logger.error(f"error: {e}", extra=extra)

    return render_template("dynamic-form_edit_TLS.html", rules = cfgserv.SchemeTypeCommunityRules, h3 = "Trusted Service Lists Information", id = tsl_id, lang = cfgserv.lang, role = cfgserv.roles, data_edit = db_data, Langs=cfgserv.eu_languages,Countries=cfgserv.eu_countries, temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "tsl/edit_db")

@rpr.route('/tsl/edit_db', methods=["GET", "POST"])
def tsl_edit_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsl_id = request.form.get("id")

    form = dict(request.form)
    form.pop("proceed")
    grouped = defaultdict(list)

    for key, value in form.items():
        match = re.match(r"(lang|text|URI)_(.*?).(\d+)", key)
        match2=re.match(r"(postal_address)_(.*?).(\d+)",key)
        if match:
            attr, prefix, index = match.groups()
            index = int(index)
            while len(grouped[prefix]) <= index:
                grouped[prefix].append({})
            grouped[prefix][index][attr] = value
        elif match2:
            attr, prefix, index = match2.groups()
            index = int(index)
            while len(grouped[attr]) <= index:
                grouped[attr].append({})
            grouped[attr][index][prefix] = value

        elif "DistributionPoints" in key:
                key_dict=key.split(".")
                grouped[key_dict[0]].append(value)
                
        else:
            grouped[key] = value

    check = func.edit_tsl_db_info(
        grouped, 
        tsl_id, 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        return redirect('/tsl/list')
        
@rpr.route('/tsl/update_tsps', methods=["GET", "POST"])
def update_tsps():

    tsl_id = request.args.get("id")
    tsps = ast.literal_eval(request.args.get("checks"))
    user_id =request.args.get("user_id")
    log_id = request.args.get("log_id")

    for elem in tsps:
        tsp_id = int(elem)

        check = func.update_tsp(tsp_id, tsl_id, session["session_id"])
        
        if check is None:
            return ("erro")

    return redirect('/tsl/list')

@rpr.route('/tsl/data_lang')
def tsl_lang():
    temp_user_id = session['temp_user_id']
    
    attributesForm={}
    tsp_id = request.args.get("id")
    form_items={
        "Lang": "lang",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        "Distribution Points": "string"
    }
    descriptions = {
        "Lang": "lang",
        "Scheme Name": "string", 
        "Uri": "string",
        "Scheme Type Community Rules": "string",
        "Policy Or Legal Notice": "string",
        "Distribution Points": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", id = tsp_id, countries=cfgserv.eu_countries, title="Trusted Lists", lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsl/tsl_db_data_lang")


@rpr.route('/tsl/tsl_db_data_lang', methods=["GET", "POST"])
def tsl_db_lang():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsl_id = request.form.get("id")

    schemeName = request.form.get('Scheme Name')
    uri = request.form.get('Uri')
    schemeTypeCommunityRules= request.form.get('Scheme Type Community Rules')
    policyLegalNotice= request.form.get('Policy Or Legal Notice')
    distributionPoints= request.form.get('Distribution Points')
    lang = request.form.get('Lang')

    db_data = func.get_data_tsl(tsl_id, session["session_id"])

    current_data_schemeName = None
    current_data_uri= None
    current_data_schemeTypeCommunityRules = None
    current_data_policyLegalNotice = None
    current_data_distributionPoints = None

    if schemeName:
        schemeName_data = {"lang": lang, "text": schemeName}
        current_data_schemeName = json.loads(db_data.get('SchemeName_lang', '[]'))
        current_data_schemeName.append(schemeName_data)
        current_data_schemeName = json.dumps(current_data_schemeName)

    if uri:
        uri_data = {"lang": lang, "URI": uri}
        current_data_uri = json.loads(db_data.get('Uri_lang', '[]'))
        current_data_uri.append(uri_data)
        current_data_uri = json.dumps(current_data_uri)
        
    if schemeTypeCommunityRules:
        schemeTypeCommunityRules_data = {"lang": lang, "URI": schemeTypeCommunityRules}
        current_data_schemeTypeCommunityRules = json.loads(db_data.get('SchemeTypeCommunityRules_lang', '[]'))
        current_data_schemeTypeCommunityRules.append(schemeTypeCommunityRules_data)
        current_data_schemeTypeCommunityRules = json.dumps(current_data_schemeTypeCommunityRules)

    if policyLegalNotice:
        policyLegalNotice_data = {"lang": lang, "text": policyLegalNotice}
        current_data_policyLegalNotice = json.loads(db_data.get('PolicyOrLegalNotice_lang', '[]'))
        current_data_policyLegalNotice.append(policyLegalNotice_data)
        current_data_policyLegalNotice = json.dumps(current_data_policyLegalNotice)

    if distributionPoints:
        distributionPoints_data = distributionPoints
        current_data_distributionPoints = json.loads(db_data.get('DistributionPoints', '[]'))
        current_data_distributionPoints.append(distributionPoints_data)
        current_data_distributionPoints = json.dumps(current_data_distributionPoints)

    check = func.tsl_db_lang(user['id'], 
                             tsl_id, 
                             current_data_schemeName, 
                             current_data_uri, 
                             current_data_schemeTypeCommunityRules,
                             current_data_policyLegalNotice, 
                             current_data_distributionPoints, 
                             session["session_id"])

    if check is None:
        return "err"
    else:   
        return redirect('/tsl/list')

# TSP
@rpr.route('/tsp/list')
def list_tsp():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsp_dict = func.get_tsp_info(user["id"], session["session_id"])
    header_table=[ "TSP Name", "Trade Name", "Postal Address", "EletronicAddress","TSP InformationURI"]

    if(tsp_dict == "err"):
        data = {}
    else:
        
        data = {}
        
        for tsp in tsp_dict:
            data_temp={
                tsp["tsp_id"]:{
                    "TSP Name": tsp["name"],
                    "Trade Name": tsp["trade_name"],
                    "Postal Address": tsp["postal_address"],
                    "EletronicAddress": tsp["EletronicAddress"],
                    "TSP InformationURI": tsp["TSPInformationURI"]
                }
            }
            data.update(data_temp)

    service_dict = func.get_service_update(user["id"], session["session_id"])
    
    list = []

    if(service_dict != "err"):
        for item in service_dict:
            name = json.loads(item["ServiceName"])
            name_txt = name[0]["text"] if name else "No Name"

            if(item["tsp_id"] != None):
                tsp_name = func.get_tsp_name(item["tsp_id"], session["session_id"])
                aux_name = json.loads(tsp_name["name"])
                tsp_name = aux_name[0]["text"] if aux_name else "No Name"

                new_item = {
                    "id": item["service_id"],
                    "name": name_txt,
                    "associated_id": item["tsp_id"],
                    "ass_name": tsp_name
                }
            else:
                new_item = {
                    "id": item["service_id"],
                    "name": name_txt,
                    "associated_id": item["tsp_id"],
                    "ass_name": ""
                }
            
            list.append(new_item)

    if(cfgserv.two_operators):
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(role == "tsl_op"):
            menu= cfgserv.service_url + "menu_tsl"
            return render_template("CertificateList.html", h1 = "Trust Service Providers", menu = menu, data=data, title="Trust Service Providers", list= list, header_table=header_table, url=cfgserv.service_url +"tsp", temp_user_id = temp_user_id)
        elif(role == "tsp_op"):
            menu= cfgserv.service_url + "menu_tsp"
            return render_template("CertificateList.html", h1 = "Trust Service Providers", menu = menu, data=data, title="Trust Service Providers", list= list, header_table=header_table, url=cfgserv.service_url +"tsp", temp_user_id = temp_user_id)
        else:
            return ("error")
    else:
        menu= cfgserv.service_url + "menu"
        return render_template("CertificateList.html", h1 = "Trust Service Providers", menu = menu, data=data, title="Trust Service Providers", list= list, header_table=header_table, url=cfgserv.service_url +"tsp", temp_user_id = temp_user_id)

@rpr.route('/tsp/create')
def create_tsp():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "Street Address" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country",
    }
    
    descriptions = {
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "Street Address": "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country",
    }

    attributesForm.update(form_items)
    
    return render_template("form_create.html", h3 = "Trusted Service Provider information form", countries=cfgserv.eu_countries, title="Trusted Service Provider", lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsp/create/db")


@rpr.route('/tsp/create/db', methods=["GET", "POST"])
def create_tsp_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    name = request.form.get('Name')
    trade_name = request.form.get('Trade Name')
    StreetAddress = request.form.get('Street Address')
    Locality= request.form.get('Locality')
    StateOrProvince= request.form.get('State Or Province')
    PostalCode= request.form.get('Postal Code')
    EletronicAddress= request.form.get('Eletronic Address')
    TSPInformationURI= request.form.get('TSP Information URI')
    country= request.form.get('Country Name')
    lang = request.form.get('Lang')

    name = '[{"lang":"' + lang + '", "text":"'+ name + '"}]'
    trade_name = '[{"lang":"' + lang + '", "text":"'+ trade_name + '"}]'
    EletronicAddress = '[{"lang":"' + lang + '", "URI":"'+ EletronicAddress + '"}]'
    TSPInformationURI = '[{"lang":"' + lang + '", "URI":"'+ TSPInformationURI + '"}]'
    PostalAddress = '[{"lang":"' + lang + '", "StreetAddress":"'+ StreetAddress + '", "Locality":"'+ Locality + '", "StateOrProvince":"'+ StateOrProvince + '", "PostalCode":"'+ PostalCode + '", "CountryName":"'+ country + '"}]'
    
    check = func.tsp_db_info(user['id'], name, trade_name, PostalAddress, EletronicAddress, TSPInformationURI, session["session_id"])

    if check is None:
        return "err"
    else:
        return redirect('/tsp/list')
        

@rpr.route('/tsp/data_lang')
def tsp_lang():
    temp_user_id = session['temp_user_id']
    
    attributesForm={}
    tsp_id = request.args.get("id")
    form_items={
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "Street Address" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country"
    }
    descriptions = {
        "Lang": "lang",
        "Name": "string",
        "Trade Name": "string",
        "Eletronic Address": "string",
        "TSP Information URI": "string",
        "Street Address" : "string",
        "Locality": "string",
        "State Or Province": "string",
        "Postal Code": "string",
        "Country Name": "country"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", id = tsp_id, countries=cfgserv.eu_countries, title="Trusted Service Provider", lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "tsp/tsp_db_data_lang")


@rpr.route('/tsp/tsp_db_data_lang', methods=["GET", "POST"])
def tsp_db_lang():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    tsp_id = request.form.get("id")

    name = request.form.get('Name')
    trade_name = request.form.get('Trade Name')
    StreetAddress = request.form.get('Street Address')
    Locality= request.form.get('Locality')
    StateOrProvince= request.form.get('State Or Province')
    PostalCode= request.form.get('Postal Code')
    CountryName= request.form.get('Country Name')
    EletronicAddress= request.form.get('Eletronic Address')
    TSPInformationURI= request.form.get('TSP Information URI')
    lang = request.form.get('Lang')

    db_data = func.get_data_tsp(tsp_id, session["session_id"])

    current_data_name = None
    current_data_trade_name = None
    current_data_postal_address = None
    current_data_EletronicAddress = None
    current_data_TSPInformationURI = None

    if name:
        name_data = {"lang": lang, "text": name}
        current_data_name = json.loads(db_data.get('name', '[]'))
        current_data_name.append(name_data)
        current_data_name = json.dumps(current_data_name)

    if trade_name:
        trade_name_data = {"lang": lang, "text": trade_name}
        current_data_trade_name = json.loads(db_data.get('trade_name', '[]'))
        current_data_trade_name.append(trade_name_data)
        current_data_trade_name = json.dumps(current_data_trade_name)

    if all([StreetAddress, Locality, StateOrProvince, PostalCode, CountryName]):
        postal_address_data = {
            "lang": lang,
            "StreetAddress": StreetAddress,
            "Locality": Locality,
            "StateOrProvince": StateOrProvince,
            "PostalCode": PostalCode,
            "CountryName": CountryName
        }
        current_data_postal_address = json.loads(db_data.get('postal_address', '[]'))
        current_data_postal_address.append(postal_address_data)
        current_data_postal_address = json.dumps(current_data_postal_address)

    if EletronicAddress:
        electronic_address_data = {"lang": lang, "URI": EletronicAddress}
        current_data_EletronicAddress = json.loads(db_data.get('EletronicAddress', '[]'))
        current_data_EletronicAddress.append(electronic_address_data)
        current_data_EletronicAddress = json.dumps(current_data_EletronicAddress)

    if TSPInformationURI:
        tsp_info_data = {"lang": lang, "URI": TSPInformationURI}
        current_data_TSPInformationURI = json.loads(db_data.get('TSPInformationURI', '[]'))
        current_data_TSPInformationURI.append(tsp_info_data)
        current_data_TSPInformationURI = json.dumps(current_data_TSPInformationURI)

    check = func.tsp_db_lang(user['id'], 
                             tsp_id, 
                             current_data_name, 
                             current_data_trade_name, 
                             current_data_postal_address,
                             current_data_EletronicAddress, 
                             current_data_TSPInformationURI, 
                             session["session_id"])

    if check is None:
        return "err"
    else:   
        return redirect('/tsp/list')


@rpr.route('/tsp/edit')
def tsp_edit():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    tsp_id = request.args.get("id")

    db_data = func.get_data_tsp_edit(tsp_id, session["session_id"])

    for key in db_data: 
        db_data[key] = json.loads(db_data[key])

    
    return render_template("dynamic-form_edit_TLS.html", h3 = "Trusted Service Provider Information", title = "Trusted Service Provider", id = tsp_id, lang = cfgserv.lang, role = cfgserv.roles, data_edit = db_data, Langs=cfgserv.eu_languages,Countries=cfgserv.eu_countries, temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "/tsp/tsp_edit_db")

@rpr.route('/tsp/tsp_edit_db', methods=["GET", "POST"])
def tsp_edit_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    tsp_id = request.form.get("id")

    form = dict(request.form)
    form.pop("proceed")
    grouped = defaultdict(list)

    for key, value in form.items():
        match = re.match(r"(lang|text|URI)_(.*?).(\d+)", key)
        match2=re.match(r"(postal_address)_(.*?).(\d+)",key)
        if match:
            attr, prefix, index = match.groups()
            index = int(index)
            while len(grouped[prefix]) <= index:
                grouped[prefix].append({})
            grouped[prefix][index][attr] = value
        elif match2:
            attr, prefix, index = match2.groups()
            index = int(index)
            while len(grouped[attr]) <= index:
                grouped[attr].append({})
            grouped[attr][index][prefix] = value

        elif "DistributionPoints" in key:
                key_dict=key.split(".")
                grouped[key_dict[0]].append(value)
                
        else:
            grouped[key] = value
    
    check = func.edit_tsp_db_info(
        grouped, 
        tsp_id, 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        return redirect('/tsp/list')
        
@rpr.route('/tsp/update_services', methods=["GET", "POST"])
def update_services():

    tsp_id = request.args.get("id")
    services = ast.literal_eval(request.args.get("checks"))
    user_id =request.args.get("user_id")
    log_id = request.args.get("log_id")

    for elem in services:
        service_id = int(elem)

        check = func.update_service(service_id, tsp_id, session["session_id"])
        
        if check is None:
            return ("erro")

    return redirect('/tsp/list')
    
# Service
@rpr.route('/service/list')
def list_service():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    service_dict = func.get_service_info(user["id"], session["session_id"])
    header_table=[ "Service Type","Service Name","Status","Status Starting Date", "Qualifier", "SchemeService Definition URI"]

    if(service_dict == "err"):
        data = {}
    else:
        data = {}
    
        for service in service_dict:
            data_temp={
                service["service_id"]:{
                    "Service Type": service["service_type"],
                    "Service Name": service["ServiceName"],
                    "Status": service["status"],
                    "Status start date": service["status_start_date"],
                    "Qualifier": service["qualifier"],
                    "SchemeService Definition URI": service["SchemeServiceDefinitionURI"]
                }
            }
            data.update(data_temp)
    list = []
    
    if(cfgserv.two_operators):
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(role == "tsl_op"):
            menu= cfgserv.service_url + "menu_tsl"
            return render_template("CertificateList.html", h1 = "Trust Services", menu = menu, data=data, title="Services", list= list, header_table=header_table, url=cfgserv.service_url +"service", temp_user_id = temp_user_id)
        elif(role == "tsp_op"):
            menu= cfgserv.service_url + "menu_tsp"
            return render_template("CertificateList.html", h1 = "Trust Services", menu = menu, data=data, title="Services", list= list, header_table=header_table, url=cfgserv.service_url +"service", temp_user_id = temp_user_id)
        else:
            return ("error")
    else:
        menu= cfgserv.service_url + "menu"
        return render_template("CertificateList.html", h1 = "Trust Services",  menu = menu, data=data, title="Services", list= list, header_table=header_table, url=cfgserv.service_url +"service", temp_user_id = temp_user_id)

@rpr.route('/service/create')
def create_service():
    
    temp_user_id = session['temp_user_id']
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Service Type": "select_type",
        "Service Name": "string",
        #"Qualifier": "select",
        "Digital Identity" : "textarea",
        "Service Status": "status",
        "Status Start Date": "full-date",
        "Scheme Service Definition URI": "string"
    }
    descriptions = {
        "Lang": "string",
        "Service Type": "Type of service provided",
        "Service Name": "Provide the service name",
        #"Qualifier": "Select applicable qualifiers",
        "Digital Identity": "Specify the digital Certificate (It's not necessary to include BEGIN or END certificate.)",
        "Status": "Service status",
        "Status Start Date": "Start date of the current status",
        "Uri": "Service URI"
    }

    attributesForm.update(form_items)
    
    return render_template("form_service.html", title="Service",status = cfgserv.ServiceStatus, lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, 
                           data = cfgserv.qualifiers, redirect_url= cfgserv.service_url + "service/create/db", qualified = cfgserv.qualified,
                           non_qualified = cfgserv.non_qualified, national = cfgserv.national, serv_cat = cfgserv.service_category)


@rpr.route('/service/create/db', methods=["GET", "POST"])
def service_tsp_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    service_type = request.form.get('category')
    service_name = request.form.get('Service Name')
    #qualifier = request.form.get('Qualifier')
    digital_identity = request.form.get('Digital Identity')
    status = request.form.get('Service Status')
    status_start_date = request.form.get('Status Start Date')
    uri = request.form.get('Scheme Service Definition URI')
    lang = request.form.get('Lang')

    ServiceName = '[{"lang":"' + lang + '", "text":"'+ service_name + '"}]'
    SchemeServiceDefinitionURI = '[{"lang":"' + lang + '", "URI":"'+ uri + '"}]'

    check = func.service_db_info(user['id'], ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, session["session_id"])

    if check is None:
        return (check)
    else:
        
        return redirect('/service/list')
       
@rpr.route('/service/data_lang')
def service_lang():
    
    temp_user_id = session['temp_user_id']
    
    service_id = request.args.get("id")

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
    
    return render_template("form.html", id = service_id, countries=cfgserv.eu_countries, title="Service", lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, 
                           data = cfgserv.qualifiers, redirect_url= cfgserv.service_url + "service/service_lang_db")


@rpr.route('/service/service_lang_db', methods=["GET", "POST"])
def service_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    service_id = request.form.get("id")

    service_name = request.form.get('Service Name')
    uri = request.form.get('Uri')
    lang = request.form.get('Lang')

    db_data = func.get_data_service(service_id, session["session_id"])
    
    current_data_ServiceName = None
    current_data_SchemeServiceDefinitionURI = None

    if service_name:
        service_name_data = {"lang": lang, "text": service_name}
        current_data_ServiceName = json.loads(db_data.get('ServiceName', '[]'))
        current_data_ServiceName.append(service_name_data)
        current_data_ServiceName = json.dumps(current_data_ServiceName)

    if uri:
        scheme_service_data = {"lang": lang, "URI": uri}
        current_data_SchemeServiceDefinitionURI = json.loads(db_data.get('SchemeServiceDefinitionURI', '[]'))
        current_data_SchemeServiceDefinitionURI.append(scheme_service_data)
        current_data_SchemeServiceDefinitionURI = json.dumps(current_data_SchemeServiceDefinitionURI)

    check = func.service_db_lang(
        service_id,
        current_data_ServiceName,
        current_data_SchemeServiceDefinitionURI,
        session["session_id"]
    )

    if check is None:
        return ("err")
    else:
        return redirect('/service/list')
       

@rpr.route('/service/edit')
def service_edit():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    service_id = request.args.get("id")

    db_data = func.get_data_service_edit(service_id, session["session_id"])

    for key in db_data: 
        db_data[key] = json.loads(db_data[key])
    
    return render_template("dynamic-form_edit_TLS.html", h3 = "Trust Service Information", title = "Service", id = service_id, lang = cfgserv.lang, role = cfgserv.roles, data_edit = db_data, Langs=cfgserv.eu_languages,Countries=cfgserv.eu_countries, temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "/service/service_edit_db")

@rpr.route('/service/service_edit_db', methods=["GET", "POST"])
def service_edit_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    service_id = request.form.get("id")

    form = dict(request.form)
    form.pop("proceed")
    grouped = defaultdict(list)

    for key, value in form.items():
        match = re.match(r"(lang|text|URI)_(.*?).(\d+)", key)
        match2=re.match(r"(postal_address)_(.*?).(\d+)",key)
        if match:
            attr, prefix, index = match.groups()
            index = int(index)
            while len(grouped[prefix]) <= index:
                grouped[prefix].append({})
            grouped[prefix][index][attr] = value
        elif match2:
            attr, prefix, index = match2.groups()
            index = int(index)
            while len(grouped[attr]) <= index:
                grouped[attr].append({})
            grouped[attr][index][prefix] = value

        elif "DistributionPoints" in key:
                key_dict=key.split(".")
                grouped[key_dict[0]].append(value)
                
        else:
            grouped[key] = value
            
    check = func.edit_service_db_info(
        grouped, 
        service_id, 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        return redirect('/service/list')
    
# lotl

@rpr.route('/lotl/update')
def update_lotl():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')

    checks = request.args.get('checks')
    checks = json.loads(checks)

    all_ids = func.get_all_tsls_ids(session["session_id"])
    all_ids = [x[0] for x in all_ids]
    
    not_seleted = list(set(all_ids) - set(map(int, checks)))

    for tsl_id in checks:
        aux = func.update_lotl(tsl_id, session["session_id"])  

    for tsl_id in not_seleted:
        aux = func.update_not_seleted_lotl(tsl_id, session["session_id"])

    return "sucess"
    
@rpr.route('/lotl/list')
def list_lotl():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    tsl_dict = func.get_lotl_tsl_info(session["session_id"])
    
    header_table=[ "Version","Sequence Number","TSL Type","Scheme Name","Scheme Territory","Issue Date","Next Update"]
    if(tsl_dict == "err"):
        data={}
    else:
        data={}

        for tsl in tsl_dict:
            if(tsl['lotl'] != None):
                if(tsl['lotl'] == 0):
                    included = False
                elif(tsl['lotl'] == 1):
                    included = True
                data_temp={
                    tsl["tsl_id"]:{
                        "Version":tsl["Version"],
                        "Sequence Number":tsl["SequenceNumber"],
                        "TSL Type":tsl["TSLType"],
                        "Scheme Name":tsl["SchemeName_lang"],
                        "Scheme Territory":tsl["schemeTerritory"],
                        "Issue Date":tsl["issue_date"],
                        "Next Update":tsl["next_update"],
                        "included":included
                    }
                }
                data.update(data_temp)
    
    return render_template("AdminList.html", h3 = "List of Trusted Lists", data=data, title="List Of Trusted Lists", menu= cfgserv.service_url + "menu_lotl", header_table=header_table, url=cfgserv.service_url +"lotl", temp_user_id = temp_user_id, servi = cfgserv.service_url + "lotl/xml")



@rpr.route('/lotl/xml', methods=["GET", "POST"])
def lotl_xml():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    user_info = func.get_user_info(user["id"], session["session_id"])
    tsl_list = []

    tsl_info = func.get_tsl_loft(session["session_id"])

    tsl_data = func.get_lotltsl_info(user["id"], session["session_id"])

    if(tsl_data == "err"):
        flash("You don't have a Lotl Trusted List created, so it's not possible to generate the XML. Please create a new Lotl TSL.", "danger")
        return redirect('/lotl/list')
    lang_based_fields = [
        "SchemeName_lang",
        "Uri_lang",
        "SchemeTypeCommunityRules_lang",
        "PolicyOrLegalNotice_lang"
    ]

    for key in lang_based_fields:
        try:
            tsl_data[key] = json.loads(tsl_data[key]) if tsl_data[key] else []
        except json.JSONDecodeError:
            extra = {'code': session["session_id"]} 
            logger.error(f"Error decoding : {key}: {tsl_data[key]}", extra=extra)
            print(f"Error decoding {key}: {tsl_data[key]}")
            tsl_data[key] = []
    
    else:
        tsl_mom = tsl_data
        dict_tsl_mom = {
            "Version":  confxml.TLSVersionIdentifier,
            "SequenceNumber":   tsl_mom["SequenceNumber"],
            "SchemeName":   tsl_mom["SchemeName_lang"],
            "SchemeInformationURI": tsl_mom["Uri_lang"],
            #"StatusDeterminationApproach":  confxml.StatusDeterminationApproach.get("EU"),
            #"SchemeTypeCommunityRules": tsl_mom["SchemeTypeCommunityRules_lang"],
            "PolicyOrLegalNotice":  tsl_mom["PolicyOrLegalNotice_lang"],
            "HistoricalInformationPeriod":  confxml.HistoricalInformationPeriod,
            "TSLLocation"	:   "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
            #"DistributionPoints" :  tsl_mom["DistributionPoints"],
            "issue_date" :  tsl_mom["issue_date"],
            "next_update":  tsl_mom["next_update"],
            "status":   tsl_mom["status"]
        }
    
        for each in tsl_info:
            dictFromDB_trusted_lists = {
                "id": each["tsl_id"],
                "Version":  confxml.TLSVersionIdentifier,
                "SequenceNumber":   each["SequenceNumber"],
                #"TSLType":  confxml.TSLType.get("EU"),
                "SchemeName":   each["SchemeName_lang"],
                "SchemeInformationURI": each["Version"],
                #"StatusDeterminationApproach":  confxml.StatusDeterminationApproach.get("EU"),
                #"SchemeTypeCommunityRules": each["SchemeTypeCommunityRules_lang"],
                "PolicyOrLegalNotice":  each["PolicyOrLegalNotice_lang"],
                #"pointers_to_other_tsl" :   each["pointers_to_other_tsl"].encode('utf-8'),
                "HistoricalInformationPeriod":  confxml.HistoricalInformationPeriod,
                "TSLLocation"	:   "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
                #"DistributionPoints" :  each["DistributionPoints"],
                "issue_date" :  each["issue_date"],
                "next_update":  each["next_update"],
                "status":   each["status"],
                "schemeTerritory": each["schemeTerritory"]
            }
            tsl_list.append(dictFromDB_trusted_lists) 
            
        file, thumbprint, xml_hash_before_sign = xml_gen_lotl_xml(user_info, tsl_list, dict_tsl_mom, session["session_id"])
        
        if(cfgserv.two_operators):
            role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
            if(role == "tsl_op"):
                menu= cfgserv.service_url + "menu_tsl"
                return render_template("download_lotl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, tsl_list = tsl_list, file_data = file, temp_user_id = temp_user_id)
            elif(role == "tsp_op"):
                menu= cfgserv.service_url + "menu_tsp"
                return render_template("download_lotl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, tsl_list = tsl_list, file_data = file, temp_user_id = temp_user_id)
            else:
                return ("error")
        else:
            if(role == "lotl_op"):
                menu= cfgserv.service_url + "menu_lotl"
                return render_template("download_lotl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, tsl_list = tsl_list, file_data = file, temp_user_id = temp_user_id)
            
            menu= cfgserv.service_url + "menu"

        return render_template("download_lotl.html", menu = menu, xml_hash_before_sign = xml_hash_before_sign, thumbprint = thumbprint, tsl_list = tsl_list, file_data = file, temp_user_id = temp_user_id)
    

@rpr.route('/lotl/tsl_list')
def list_tsl_lotl():
        
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    tsl_dict = func.get_tsl_info(user["id"], session["session_id"])
    
    header_table=[ "Version","Sequence Number","TSL Type","Scheme Name","Scheme Territory","Issue Date","Next Update"]
    if(tsl_dict == "err"):
        data={}
    else:
        data={}

        for tsl in tsl_dict:
            data_temp={
                tsl["tsl_id"]:{
                    "Version":tsl["Version"],
                    "Sequence Number":tsl["SequenceNumber"],
                    "TSL Type":tsl["TSLType"],
                    "Scheme Name":tsl["SchemeName_lang"],
                    "Scheme Territory":tsl["schemeTerritory"],
                    "Issue Date":tsl["issue_date"],
                    "Next Update":tsl["next_update"]
                }
            }
            data.update(data_temp)
    
    tsp_dict = func.get_tsp_update(user["id"], session["session_id"])
    
    list = []
    if(tsp_dict != "err"):

        for item in tsp_dict:
            name = json.loads(item["name"])
            
            name_txt = name[0]["text"] if name else "No Name"
            
            new_item = {
                "id": item["tsp_id"],
                "name": name_txt,
                "associated_id": item["tsl_id"]
            }
            
            list.append(new_item)
    if(cfgserv.two_operators):
        role = func.check_role_user(session[temp_user_id]['id'], session["session_id"])
        if(role == "tsl_op"):
            menu= cfgserv.service_url + "menu_lotl"
            return render_template("CertificateList.html", h1 = "LoTL Information", menu = menu, data=data, title="Trusted Lists (lotl)", list= list, header_table=header_table, url=cfgserv.service_url +"lotl", temp_user_id = temp_user_id)
        else:
            return ("error")
    else:
        menu= cfgserv.service_url + "menu_lotl"
        return render_template("CertificateList.html", h1 = "LoTL Information", menu = menu, data=data, title="Trusted Lists (lotl)", list= list, header_table=header_table, url=cfgserv.service_url +"lotl", temp_user_id = temp_user_id)
        
    
@rpr.route('/lotl/create')
def create_tsl_lotl():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    attributesForm={}

    form_items={
        "Lang": "lang",
        "Scheme Name": "string", 
        "Scheme Information URI": "string",
        "Policy Or Legal Notice": "string",
        #"Scheme Type Community Rules": "rules",
        "Additional Information": "string"
    }
    descriptions = {
        "Lang": "lang",
        "Scheme Name": "string", 
        "Scheme Information URI": "string",
        "Policy Or Legal Notice": "string",
        #"Scheme Type Community Rules": "rules",
        "Additional Information": "string"
    }

    attributesForm.update(form_items)
    rules = cfgserv.SchemeTypeCommunityRules
            
    return render_template("form_create.html", h3 = "Trusted List LoTL information form", countries=cfgserv.eu_countries, title="Trusted List LoTL", rules = rules, 
                           status = cfgserv.statusDetermination,  TSLType= cfgserv.TSLType, lang = cfgserv.eu_languages, 
                           desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, 
                           redirect_url= cfgserv.service_url + "lotl/create/db")

@rpr.route('/lotl/create/db', methods=["GET", "POST"])
def create_lotl_db():
    
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')

    Version = confxml.TLSVersionIdentifier
    Sequence_number = 1
    TSLType = request.form.get('TSL Type')
    SchemeName_lang = request.form.get('Scheme Name')
    Uri_lang = request.form.get('Scheme Information URI')
    
    #options = request.form.getlist('rules')
 
    schemeTerritory = request.form.get('Scheme Territory')
    PolicyOrLegalNotice_lang = request.form.get('Policy Or Legal Notice')
    PointerstootherTSL = request.form.get('Pointers to other TSL')
    DistributionPoints = request.form.get('Distribution Points')
    Issue_date = datetime.now()
    NextUpdate = Issue_date + timedelta(days=6*30)
    Status = request.form.get('Status determination approach')
    AdditionalInformation = request.form.get('Additional Information')
    lang = request.form.get('Lang')

    #SchemeTypeCommunityRules_lang = ", ".join(options)

    SchemeName_lang = '[{"lang":"' + lang + '", "text":"'+ SchemeName_lang + '"}]'
    Uri_lang = '[{"lang":"' + lang + '", "URI":"'+ Uri_lang + '"}]'
    #SchemeTypeCommunityRules_lang = '[{"lang":"' + lang + '", "URI":"'+ SchemeTypeCommunityRules_lang + '"}]'
    PolicyOrLegalNotice_lang = '[{"lang":"' + lang + '", "text":"'+ PolicyOrLegalNotice_lang + '"}]'
    
    check = func.check_country(user['issuing_country'], session["session_id"])
    check = func.tsl_db_info_lotl(user['id'], Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang,
                             PolicyOrLegalNotice_lang, PointerstootherTSL, DistributionPoints, Issue_date, NextUpdate, Status, 
                             AdditionalInformation, schemeTerritory, check, session["session_id"])
    
    if check is None:
        return ("err")
    else:   
        return redirect('/lotl/tsl_list')
    
@rpr.route('lotl/edit', methods=["GET", "POST"])
def lotl_tsl_edit():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    if not request.args.get("id"):
        return ""
    
    tsl_id = request.args.get("id")

    db_data = func.get_data_lotl_tsl_edit(tsl_id, session["session_id"])

    for key in db_data:
        if db_data[key]:
            try:
                db_data[key] = json.loads(db_data[key])
            except json.JSONDecodeError as e:
                extra = {'code': session["session_id"]} 
                logger.error(f"error: {e}", extra=extra)

    return render_template("dynamic-form_edit_TLS.html", rules = cfgserv.SchemeTypeCommunityRules, h3 = "Lotl Information", id = tsl_id, 
                           lang = cfgserv.lang, role = cfgserv.roles, data_edit = db_data, Langs=cfgserv.eu_languages,
                           Countries=cfgserv.eu_countries, temp_user_id=temp_user_id, redirect_url= cfgserv.service_url + "lotl/edit_db")

@rpr.route('/lotl/edit_db', methods=["GET", "POST"])
def lotl_tsl_edit_db():

    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')

    tsl_id = request.form.get("id")

    form = dict(request.form)
    form.pop("proceed")
    grouped = defaultdict(list)

    for key, value in form.items():
        match = re.match(r"(lang|text|URI)_(.*?).(\d+)", key)
        match2=re.match(r"(postal_address)_(.*?).(\d+)",key)
        if match:
            attr, prefix, index = match.groups()
            index = int(index)
            while len(grouped[prefix]) <= index:
                grouped[prefix].append({})
            grouped[prefix][index][attr] = value
        elif match2:
            attr, prefix, index = match2.groups()
            index = int(index)
            while len(grouped[attr]) <= index:
                grouped[attr].append({})
            grouped[attr][index][prefix] = value

        elif "DistributionPoints" in key:
                key_dict=key.split(".")
                grouped[key_dict[0]].append(value)
                
        else:
            grouped[key] = value

    check = func.edit_lotl_tsl_db_info(
        grouped, 
        tsl_id, 
        session["session_id"]
    )

    if check is None:
        return ("erro")
    else:
        return redirect('/lotl/tsl_list')

@rpr.route('/lotl/data_lang')
def lotl_tsl_lang():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]

    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')
    
    attributesForm={}
    tsp_id = request.args.get("id")
    form_items={
        "Lang": "lang",
        "Scheme Name": "string", 
        "Uri": "string",
        "Policy Or Legal Notice": "string",
        "Scheme Type Community Rules": "string"
    }
    descriptions = {
        "Lang": "lang",
        "Scheme Name": "string", 
        "Uri": "string",
        "Policy Or Legal Notice": "string",
        "Scheme Type Community Rules": "string"
    }

    attributesForm.update(form_items)
    
    return render_template("form.html", id = tsp_id, countries=cfgserv.eu_countries, title="Trusted Lists", lang = cfgserv.eu_languages, desc = descriptions, attributes = attributesForm, temp_user_id = temp_user_id, redirect_url= cfgserv.service_url + "lotl/lotl_tsl_db_data_lang")

@rpr.route('/lotl/lotl_tsl_db_data_lang', methods=["GET", "POST"])
def lotl_tsl_db_lang():
    temp_user_id = session['temp_user_id']
    user = session[temp_user_id]
    
    role = func.check_role_user(user["id"], session["session_id"])
    if(role != "lotl_op"):
        return redirect('/menu')

    tsl_id = request.form.get("id")

    schemeName = request.form.get('Scheme Name')
    uri = request.form.get('Uri')
    policyLegalNotice= request.form.get('Policy Or Legal Notice')
    schemeTypeCommunityRules= request.form.get('Scheme Type Community Rules')
    lang = request.form.get('Lang')

    db_data = func.get_data_tsl(tsl_id, session["session_id"])

    current_data_schemeName = None
    current_data_uri= None
    current_data_policyLegalNotice = None
    current_data_schemeTypeCommunityRules = None

    if schemeName:
        schemeName_data = {"lang": lang, "text": schemeName}
        current_data_schemeName = json.loads(db_data.get('SchemeName_lang', '[]'))
        current_data_schemeName.append(schemeName_data)
        current_data_schemeName = json.dumps(current_data_schemeName)

    if uri:
        uri_data = {"lang": lang, "URI": uri}
        current_data_uri = json.loads(db_data.get('Uri_lang', '[]'))
        current_data_uri.append(uri_data)
        current_data_uri = json.dumps(current_data_uri)
        
    if policyLegalNotice:
        policyLegalNotice_data = {"lang": lang, "text": policyLegalNotice}
        current_data_policyLegalNotice = json.loads(db_data.get('PolicyOrLegalNotice_lang', '[]'))
        current_data_policyLegalNotice.append(policyLegalNotice_data)
        current_data_policyLegalNotice = json.dumps(current_data_policyLegalNotice)
        
    if schemeTypeCommunityRules:
        schemeTypeCommunityRules_data = {"lang": lang, "URI": schemeTypeCommunityRules}
        current_data_schemeTypeCommunityRules = json.loads(db_data.get('SchemeTypeCommunityRules_lang', '[]'))
        current_data_schemeTypeCommunityRules.append(schemeTypeCommunityRules_data)
        current_data_schemeTypeCommunityRules = json.dumps(current_data_schemeTypeCommunityRules)

    check = func.lotl_tsl_db_lang(user['id'], 
                             tsl_id, 
                             current_data_schemeName, 
                             current_data_uri, 
                             current_data_policyLegalNotice, 
                             current_data_schemeTypeCommunityRules,
                             session["session_id"])

    if check is None:
        return "err"
    else:   
        return redirect('/lotl/tsl_list')


# logout
@rpr.route('/logout')
def logout():
    session.clear()
    
    return redirect(url_for('RPR.initial_page'))
