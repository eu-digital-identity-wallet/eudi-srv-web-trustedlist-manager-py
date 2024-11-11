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
from http.client import HTTPException
import json
import os

from flask import Flask, render_template
from flask_cors import CORS
from flask_session import Session

from app import create_app

from app.app_config.config import ConfService

app = create_app()
    
#certs_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'certs'))

#cert_path = os.path.join(certs_folder, 'cert.pem')
#key_path = os.path.join(certs_folder, 'key.pem')

#app.run(ssl_context=(cert_path, key_path), debug=True)