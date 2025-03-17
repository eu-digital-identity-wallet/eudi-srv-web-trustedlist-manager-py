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
This xml_config.py contains configuration data for the xml generator. 

NOTE: You should only change it if you understand what you're doing.
"""

class ConfXML:

    TLSVersionIdentifier=6
    TSLType={
        "EU":"http://trustedlist.eudiw.dev/TrstSvc/TrustedList/TSLType/EUgeneric",
        "EUDIW":"http://trustedlist.eudiw.dev/TrstSvc/TrustedList/TSLType/EUlistofthelists"
    }

    StatusDeterminationApproach={
        "EU":"http://trustedlist.eudiw.devTrstSvc/TrustedList/StatusDetn/EUappropriate",
        "EUDIW":"http://trustedlist.eudiw.dev/TrstSvc/TrustedList/StatusDetn/EUlistofthelists"
    }

    SchemeTypeCommunityRules={
        "EUDIW":"http://trustedlist.eudiw.dev/TrstSvc/TrustedList/schemerules/EUlistofthelists"
    }

    DistributionPoints={
        "EUDIW":"https://trustedlist.eudiw.dev/tools/lotl/eu-lotl.xml"
    }

    HistoricalInformationPeriod=65535

    #months
    validity=6