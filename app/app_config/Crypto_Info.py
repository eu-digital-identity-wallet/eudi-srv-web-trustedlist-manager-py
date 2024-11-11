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
This Crypto_info.py contains crypto configuration data for the Web RelyingParty Registration service. 

NOTE: You should only change it if you understand what you're doing.
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from flask import  session

from .config import ConfService as cfgserv

class Crypto_Info:

    key_size=2048
    exponent=65537