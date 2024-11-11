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
This db.py file contains the function related to the connection with the DB.

"""
import pymysql
from app_config.database import ConfDataBase

def get_db_connection():
    try:
        connection = pymysql.connect(
            host=ConfDataBase.DATABASE['host'],
            port=ConfDataBase.DATABASE['port'],
            user=ConfDataBase.DATABASE['user'],
            password=ConfDataBase.DATABASE['password'],
            database=ConfDataBase.DATABASE['database']
        )
        return connection
    except pymysql.Error as e:
        print(f"Error connecting to MariaDB: {e}")
        return None