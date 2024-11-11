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
This user.py file contains class User to create user id .

"""
import hashlib
import base64
import uuid

class User:
    def __init__(self, family_name, given_name, birth_date, issuing_country, issuance_authority):
        self.id = str(uuid.uuid4())
        self.issuing_country = issuing_country
        self.issuance_authority = issuance_authority
        self.hash = self.determine_hash(family_name, given_name, birth_date, issuing_country)

    def determine_hash(self, family_name, given_name, birth_date, country):
        
        combined_info = f"{family_name};{given_name};{birth_date};{country}"
        
        sha = hashlib.sha256()
        sha.update(combined_info.encode('utf-8'))
        
        return base64.b64encode(sha.digest()).decode('utf-8')

# user = User("Doe", "John", "1990-01-01", "PT", "Some Authority", "Admin")
# print(f"ID: {user.id}")
# print(f"Hash: {user.hash}")