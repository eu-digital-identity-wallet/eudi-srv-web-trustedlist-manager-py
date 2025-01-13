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
This models.py file contains functions related to queries to add data to DB (user, Relying Party, access_certificate).

"""
import pymysql
from app_config.config import ConfService
from db import get_db_connection as conn


def check_user(hash_pid, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT operator_id
                FROM scheme_operators
                WHERE pid_hash = %s
            """
            
            cursor.execute(select_query, (hash_pid,))
            result = cursor.fetchone()
            
            if result:
                user_id = result[0]
                # extra = {'code': log_id}
                # logger.info(f"User, {user_id}, already exists.", extra=extra)
                print(f"User, {user_id}, already exists.")
                return user_id
            else:
                # extra = {'code': log_id}
                # logger.info("User with hash_pid not found.", extra=extra)
                print("User with hash_pid not found.")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        # extra = {'code': log_id}
        # logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_user_id_by_hash_pid(hash_pid, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT operator_id
                FROM scheme_operators
                WHERE hash_pid = %s
            """
            
            cursor.execute(select_query, (hash_pid,))
            
            result = cursor.fetchone()

            if result:
                user_id = result[0]
                
                #extra = {'code': log_id} 
                #logger.info(f"User found: {cursor.lastrowid}.", extra=extra)
                return user_id
            else:
                #extra = {'code': log_id} 
                #logger.info(f"No user found with the hash_pid.", extra=extra)
                print(f"No user found with the hash_pid.")
                return None

    except pymysql.MySQLError as e:
        
        #extra = {'code': log_id} 
        #logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_relying_party_names_by_user_id(user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT name, relyingParty_id
                FROM relying_party
                WHERE user_id = %s
            """
            
            cursor.execute(select_query, (user_id,))
            
            result = cursor.fetchall()

            if result: 
                relying_party_data = [
                    {"name": row[0], "relyingParty_id": row[1]} 
                    for row in result
                ]
                #extra = {'code': log_id} 
                #logger.info(f"Name found for the user_id: {user_id}", extra=extra)
                return relying_party_data
            else:
                #extra = {'code': log_id} 
                #logger.info(f"No name found for the user_id: {user_id}", extra=extra)
                print(f"No name found for the user_id: {user_id}")
            

    except pymysql.MySQLError as e:
        #extra = {'code': log_id} 
        #logger.error(f"Error fetching relying party names: {e}", extra=extra)
        print(f"Error fetching relying party names: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def insert_user(pid_hash, user_name, country_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = "INSERT INTO scheme_operators (operator_name_lang, pid_hash, country_id) VALUES (%s, %s, %s)"
            
            cursor.execute(insert_query, (user_name, pid_hash, country_id,))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"User successfully added. New user ID: {cursor.lastrowid}", extra=extra)

            print(f"User successfully added. New user ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error inserting user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()



def insert_user_info(role, opName_en, address, locality, stateProvince, postalCode, electronicAddress, id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE scheme_operators 
                                SET operator_role = %s, operator_name_en = %s, StreetAddress = %s, Locality = %s, 
                                StateOrProvince = %s, PostalCode = %s, ElectronicAddress = %s
                                WHERE operator_id = %s
                            """
            cursor.execute(insert_query, (role, opName_en, address, locality, stateProvince, postalCode, electronicAddress, id,))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"User successfully added. New user ID: {cursor.lastrowid}", extra=extra)

            print(f"User successfully updated. User updated ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def check_country(user_country, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT country_id
                FROM countries
                WHERE country_code = %s
            """
            
            cursor.execute(select_query, (user_country,))
            result = cursor.fetchone()
            
            if result:
                country_id = result[0]
                # extra = {'code': log_id}
                # logger.info(f"User, {country_id}, already exists.", extra=extra)
                print(f"User, {country_id}, already exists.")
                return country_id
            else:
                # extra = {'code': log_id}
                # logger.info("Country not found.", extra=extra)
                print("Country not found.")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        # extra = {'code': log_id}
        # logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()



def insert_tsl_info(Version, Sequence_number, TSLType, SchemeName_lang, SchemeName_en, Uri_lang,Uri_en, SchemeTypeCommunityRules_lang,
                    SchemeTypeCommunityRules_en, PolicyOrLegalNotice_lang, PolicyOrLegalNotice_en, PointerstootherTSL, 
                    DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, country, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                            INSERT INTO trusted_lists 
                            (Version, SequenceNumber, TSLType, SchemeName_lang, SchemeName_en, Uri_lang, Uri_en, SchemeTypeCommunityRules_lang, 
                            SchemeTypeCommunityRules_en, PolicyOrLegalNotice_lang, PolicyOrLegalNotice_en, pointers_to_other_tsl, 
                            DistributionPoints, issue_date, next_update, status, Additional_Information, country_id) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (Version, Sequence_number, TSLType, SchemeName_lang, SchemeName_en, Uri_lang,Uri_en, SchemeTypeCommunityRules_lang,
                    SchemeTypeCommunityRules_en, PolicyOrLegalNotice_lang, PolicyOrLegalNotice_en, PointerstootherTSL, 
                    DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, country,))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"TSL successfully added. New TSL ID: {cursor.lastrowid}", extra=extra)

            print(f"TSL successfully added. New TSL ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting TSL: {e}", extra=extra)
        print(f"Error inserting TSL: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()



def update_user_tsl(id, check, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE scheme_operators 
                                SET tsl_id = %s
                                WHERE operator_id = %s
                            """
            cursor.execute(insert_query, (check, id))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"User successfully added. New user ID: {cursor.lastrowid}", extra=extra)

            print(f"User successfully updated. User updated ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def check_role_user(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT operator_role
                FROM scheme_operators
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            result = cursor.fetchone()
            
            if result:
                role = result[0]
                # extra = {'code': log_id}
                # logger.info(f"User, {role}, already exists.", extra=extra)
                return role
            else:
                # extra = {'code': log_id}
                # logger.info("User not found.", extra=extra)
                print("User not found.")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        # extra = {'code': log_id}
        # logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_user_tsl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT tsl_id
                FROM scheme_operators
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                user_id = result[0]
                
                #extra = {'code': log_id} 
                #logger.info(f"User found: {cursor.lastrowid}.", extra=extra)
                return user_id
            else:
                #extra = {'code': log_id} 
                #logger.info(f"No user found with the hash_pid.", extra=extra)
                print(f"No user found with the ID.")
                return None

    except pymysql.MySQLError as e:
        
        #extra = {'code': log_id} 
        #logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def insert_tsp_info(tsl_id, name, trade_name, StreetAddress, Locality, StateOrProvince, PostalCode, 
                             CountryName, EletronicAddress, TSPInformationURI, country, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                            INSERT INTO trust_service_providers 
                            (tsl_id, name, trade_name, StreetAddress, Locality, StateOrProvince, PostalCode, CountryName, EletronicAddress,
                            TSPInformationURI, country) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (tsl_id, name, trade_name, StreetAddress, Locality, StateOrProvince, PostalCode, 
                             CountryName, EletronicAddress, TSPInformationURI, country,))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"TSP successfully added. New TSL ID: {cursor.lastrowid}", extra=extra)

            print(f"TSP successfully added. New TSL ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting TSP: {e}", extra=extra)
        print(f"Error inserting TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_tsp_tsl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT tsp_id
                FROM trust_service_providers
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                user_id = result[0]
                
                #extra = {'code': log_id} 
                #logger.info(f"TSP found: {cursor.lastrowid}.", extra=extra)
                return user_id
            else:
                #extra = {'code': log_id} 
                #logger.info(f"No TSP found with the TSL.", extra=extra)
                print(f"No TSP found with the TSL.")
                return None

    except pymysql.MySQLError as e:
        
        #extra = {'code': log_id} 
        #logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def insert_service_info(tsp_id, service_type, service_name_lang, service_name_en, qualifier, digital_identity, status, status_start_date, uri, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                            INSERT INTO trust_services 
                            (tsp_id, service_type, service_name_lang, service_name_en, qualifier, digital_identity, status, status_start_date, uri) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (tsp_id, service_type, service_name_lang, service_name_en, qualifier, digital_identity, status, status_start_date, uri,))
            
            connection.commit()
            
            # extra = {'code': log_id} 
            # logger.info(f"TSP successfully added. New TSL ID: {cursor.lastrowid}", extra=extra)

            print(f"SERVICE successfully added. New SERVICE ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        # extra = {'code': log_id} 
        # logger.error(f"Error inserting SERVICE: {e}", extra=extra)
        print(f"Error inserting SERVICE: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_tsl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT *
                FROM trusted_lists
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                tsl_info = dict(zip(column_names, result))
                
                return tsl_info
            else:
                print(f"No TSL found with the ID.")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSL info: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_user(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT *
                FROM scheme_operators
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_info = dict(zip(column_names, result))
                
                return user_info
            else:
                print(f"No USER found with the ID.")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_tsp(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT *
                FROM trust_service_providers
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                tsp_info = dict(zip(column_names, result))
                
                return tsp_info
            else:
                print(f"No TSP found with the ID.")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSP info: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_service(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT *
                FROM trust_services
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                service_info = dict(zip(column_names, result))
                
                return service_info
            else:
                print(f"No Service found with the ID.")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching Service info: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()