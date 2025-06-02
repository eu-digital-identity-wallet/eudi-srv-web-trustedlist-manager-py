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
This manages necessary data and it's removal 

"""

import json
import threading
from datetime import datetime

from .app_config.config import ConfService as cfgservice
import requests


oid4vp_requests = {}
p12_temp={}
certificate_data_List={}


################################################
## To be moved to a file with scheduled jobs

scheduler_call = 300  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    """Function to clear parRequests"""
    now = int(datetime.timestamp(datetime.now()))
    #print("Job scheduled: clear_par() at " + str(now))

    
    for id in oid4vp_requests.copy():
        if datetime.now() > oid4vp_requests[id]["expires"]:
            #cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            oid4vp_requests.pop(id)
    for id in p12_temp.copy():
        if datetime.now() > p12_temp[id]["expires"]:
            #cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            p12_temp.pop(id)
    for id in certificate_data_List.copy():
        if datetime.now() > certificate_data_List[id]["expires"]:
            #cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            certificate_data_List.pop(id)

def run_scheduler():
    #print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()