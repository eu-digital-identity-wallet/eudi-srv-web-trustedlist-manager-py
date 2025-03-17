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
This models.py file contains functions related to queries to add data to DB (user, TSL, TSP, service, etc...).

"""
from app import logger
import pymysql
from app_config.config import ConfService
from db import get_db_connection as conn
import json
import pymysql.cursors


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
                
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {hash_pid}", extra=extra)
                print(f"Getting OPERATOR information: {hash_pid}")
                return user_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR information", extra=extra)
                print(f"Error Getting OPERATOR information")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error checking user: {e}", extra=extra)
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
                
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {hash_pid}", extra=extra)
                print(f"Getting OPERATOR information: {hash_pid}")
                return user_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR information", extra=extra)
                print(f"Error Getting OPERATOR information")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def insert_user(pid_hash, user_name, issuing_country, country_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = "INSERT INTO scheme_operators (pid_hash, country, country_id) VALUES (%s, %s, %s)"
            
            cursor.execute(insert_query, (pid_hash, issuing_country, country_id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"OPERATOR successfully added. New OPERATOR ID: {cursor.lastrowid}", extra=extra)

            print(f"OPERATOR successfully added. New OPERATOR ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error inserting user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()



def insert_user_info(role, operator_name, PostalAddress, electronicAddress, id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE scheme_operators 
                                SET operator_role = %s, operator_name = %s, postal_address = %s, EletronicAddress = %s
                                WHERE operator_id = %s
                            """
            cursor.execute(insert_query, (role, operator_name, PostalAddress, electronicAddress, id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"OPERATOR successfully updated: {id}", extra=extra)

            print(f"OPERATOR successfully updated: {id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
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
                
                extra = {'code': log_id} 
                logger.error(f"Getting Countries information, for the Country Code: {user_country}", extra=extra)
                print(f"Getting Countries information, for the Country Code: {user_country}")
                return country_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting Countries information, for the Country Code: {user_country}", extra=extra)
                print(f"Error Getting Countries information, for the Country Code: {user_country}")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()



def insert_tsl_info(user_id, Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang,
                    PolicyOrLegalNotice_lang, PointerstootherTSL, 
                    DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, schemeTerritory, lotl, country, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                            INSERT INTO trusted_lists 
                            (Version, SequenceNumber, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang, schemeTerritory,
                            PolicyOrLegalNotice_lang, pointers_to_other_tsl, 
                            DistributionPoints, issue_date, next_update, status, Additional_Information, country_id, operator_id, lotl) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (Version, Sequence_number, TSLType, SchemeName_lang, Uri_lang, SchemeTypeCommunityRules_lang, 
                    schemeTerritory, PolicyOrLegalNotice_lang, PointerstootherTSL, 
                    DistributionPoints, Issue_date, NextUpdate, Status, AdditionalInformation, country, user_id, lotl,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSL successfully added. New TSL ID: {cursor.lastrowid}", extra=extra)

            print(f"TSL successfully added. New TSL ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting TSL: {e}", extra=extra)
        print(f"Error inserting TSL: {e}")
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
                
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {id}", extra=extra)
                print(f"Getting OPERATOR information: {id}")
                return role
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR information: {id}", extra=extra)
                print(f"Error Getting OPERATOR information: {id}")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error checking user: {e}", extra=extra)
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
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trusted_lists
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchall()
            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSL information, for the OPERATOR: {id}", extra=extra)
                print(f"Getting TSL information, for the OPERATOR: {id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information, for the OPERATOR: {id}", extra=extra)
                print(f"Error Getting TSL information, for the OPERATOR: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def insert_tsp_info(user_id, name, trade_name, PostalAddress, EletronicAddress, TSPInformationURI, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            
            insert_query = """
                            INSERT INTO trust_service_providers 
                            (name, trade_name, postal_address, EletronicAddress, TSPInformationURI, operator_id) 
                            VALUES (%s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (name, trade_name, PostalAddress, EletronicAddress, TSPInformationURI, user_id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSP successfully added. New TSP ID: {cursor.lastrowid}", extra=extra)

            print(f"TSP successfully added. New TSP ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting TSP: {e}", extra=extra)
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
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information, for the TSL: {id}", extra=extra)
                print(f"Getting TSP information, for the TSL: {id}")
                return user_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the TSL: {id}", extra=extra)
                print(f"Error Getting TSP information, for the TSL: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_service_tsp(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT service_id
                FROM trust_services
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                user_id = result[0]
                
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information, for the TSP: {id}", extra=extra)
                print(f"Getting SERVICE information, for the TSP: {id}")
                return user_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting Service information, for the TSP: {id}", extra=extra)
                print(f"Error Getting Service information, for the TSP: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_tsp(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT *
                FROM trust_service_providers
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_id = dict(zip(column_names, result))
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information: {id}", extra=extra)
                print(f"Getting TSP information: {id}")

                return user_id
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information: {id}", extra=extra)
                print(f"Error Getting TSP information: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()



def insert_service_info(user_id, ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, qualifier, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                            INSERT INTO trust_services 
                            (ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, qualifier, operator_id) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """
            
            cursor.execute(insert_query, (ServiceName, SchemeServiceDefinitionURI, digital_identity, service_type, status, status_start_date, qualifier, user_id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"SERVICE successfully added. New SERVICE ID: {cursor.lastrowid}", extra=extra)

            print(f"SERVICE successfully added. New SERVICE ID: {cursor.lastrowid}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting SERVICE: {e}", extra=extra)
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

                extra = {'code': log_id} 
                logger.error(f"Getting TSL information: {id}", extra=extra)
                print(f"Getting TSL information: {id}")
                
                return tsl_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information: {id}", extra=extra)
                print(f"Erro Getting TSL information: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSL info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)

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
                
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {id}", extra=extra)
                print(f"Getting OPERATOR information: {id}")

                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR information: {id}", extra=extra)
                print(f"Error Getting OPERATOR information: {id}")
                return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)

        print(f"Error fetching USER info: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_tsp(user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trust_service_providers
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (user_id,))
            
            result = cursor.fetchall()

            if result:
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information, for the OPERATOR: {user_id}", extra=extra)
                print(f"Getting TSP information, for the OPERATOR: {user_id}")
                        
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the OPERATOR: {user_id}", extra=extra)
                print(f"Error Getting TSP information, for the OPERATOR: {user_id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSP info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_service(user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trust_services
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (user_id,))
            
            result = cursor.fetchall()

            if result:
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information, for the OPERATOR: {user_id}", extra=extra)
                print(f"Getting SERVICE information, for the OPERATOR: {user_id}")
                
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information, for the OPERATOR: {user_id}", extra=extra)
                print(f"Error Getting SERVICE information, for the OPERATOR: {user_id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching Service info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_service(service_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT ServiceName, SchemeServiceDefinitionURI
                FROM trust_services
                WHERE service_id = %s
            """
            
            cursor.execute(select_query, (service_id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                service_info = dict(zip(column_names, result))

                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information: {service_id}", extra=extra)
                print(f"Getting SERVICE information: {service_id}")
                
                return service_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information: {service_id}", extra=extra)
                print(f"Error Getting SERVICE information: {service_id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching Service info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_op(id, log_id):
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
 
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {id}", extra=extra)
                print(f"Getting OPERATOR information: {id}")
                
                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR information: {id}", extra=extra)
                print(f"Error Getting OPERATOR information: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def update_data_op(current_data_operator_name, current_data_postal_address, current_data_electronicAddress, id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            updates = []
            values = []
            if current_data_operator_name:
                updates.append("operator_name = %s")
                values.append(current_data_operator_name)
            
            if current_data_postal_address:
                updates.append("postal_address = %s")
                values.append(current_data_postal_address)
            
            if current_data_electronicAddress:
                updates.append("EletronicAddress = %s")
                values.append(current_data_electronicAddress)
            
            if updates:
                query = f"""
                    UPDATE scheme_operators
                    SET {', '.join(updates)}
                    WHERE operator_id = %s
                """
                values.append(id)
                
                cursor.execute(query, values)
                connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"OPERATOR successfully updated: {id}", extra=extra)

            print(f"OPERATOR successfully updated: {id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def edit_op(grouped, user_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            operator_name = json.dumps(grouped['operator_name'])
            electronic_address = json.dumps(grouped['EletronicAddress'])
            postal_address = json.dumps(grouped['postal_address'])

            insert_query = """
                                UPDATE scheme_operators 
                                SET operator_name = %s, EletronicAddress = %s, postal_address = %s
                                WHERE operator_id = %s
                            """
            cursor.execute(insert_query, (operator_name, electronic_address, postal_address, user_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"OPERATOR successfully updated: {user_id}", extra=extra)

            print(f"OPERATOR successfully updated: {user_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def update_data_tsp(tsp_id, current_data_name, current_data_trade_name, current_data_postal_address,
                             current_data_EletronicAddress, current_data_TSPInformationURI, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            updates = []
            values = []

            if current_data_name:
                updates.append("name = %s")
                values.append(current_data_name)
            
            if current_data_trade_name:
                updates.append("trade_name = %s")
                values.append(current_data_trade_name)
            
            if current_data_postal_address:
                updates.append("postal_address = %s")
                values.append(current_data_postal_address)
            
            if current_data_EletronicAddress:
                updates.append("EletronicAddress = %s")
                values.append(current_data_EletronicAddress)
            
            if current_data_TSPInformationURI:
                updates.append("TSPInformationURI = %s")
                values.append(current_data_TSPInformationURI)


            if updates:
                insert_query = f"""
                    UPDATE trust_service_providers
                    SET {', '.join(updates)}
                    WHERE tsp_id = %s
                """
                values.append(tsp_id)

                cursor.execute(insert_query, values)
                connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSP successfully updated: {tsp_id}", extra=extra)

            print(f"TSP successfully updated: {tsp_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def update_data_service(service_id, current_data_ServiceName, current_data_SchemeServiceDefinitionURI, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            updates = []
            values = []

            if current_data_ServiceName:
                updates.append("ServiceName = %s")
                values.append(current_data_ServiceName)

            if current_data_SchemeServiceDefinitionURI:
                updates.append("SchemeServiceDefinitionURI = %s")
                values.append(current_data_SchemeServiceDefinitionURI)

            if updates:  
                insert_query = f"""
                    UPDATE trust_services
                    SET {', '.join(updates)}
                    WHERE service_id = %s
                """
                values.append(service_id)

                cursor.execute(insert_query, values)
                connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"SERVICE successfully updated: {service_id}", extra=extra)

            print(f"service successfully updated: {service_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_op_edit(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT operator_name, EletronicAddress, postal_address
                FROM scheme_operators
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_info = dict(zip(column_names, result))
                
                extra = {'code': log_id} 
                logger.error(f"Getting OPERATOR information: {id}", extra=extra)
                print(f"Getting OPERATOR information: {id}")
                
                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting OPERATOR informatio: {id}", extra=extra)
                print(f"Error Getting TSL information: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error fetching USER info: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_data_edit_tsl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT schemeTerritory
                FROM trusted_lists
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_info = dict(zip(column_names, result))

                extra = {'code': log_id} 
                logger.error(f"Getting TSL information: {id}", extra=extra)
                print(f"Getting TSL information: {id}")
                
                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information: {id}", extra=extra)
                print(f"Error Getting TSL information: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

def edit_tsl(grouped, tsl_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            insert_query = """
                                UPDATE trusted_lists 
                                SET schemeTerritory = %s
                                WHERE tsl_id = %s
                            """
            cursor.execute(insert_query, (grouped['SchemeCountry'], tsl_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSL successfully updated: {tsl_id}", extra=extra)

            print(f"TSL successfully updated: {tsl_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_tsp_edit(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT name, postal_address, trade_name, EletronicAddress, TSPInformationURI
                FROM trust_service_providers
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_info = dict(zip(column_names, result))
                
                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the TSP: {id}", extra=extra)
                print(f"Error Getting TSP information, for the TSP: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def edit_tsp(grouped, tsp_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            name = json.dumps(grouped['name'])
            postal_address = json.dumps(grouped['postal_address'])
            trade_name = json.dumps(grouped['trade_name'])
            electronic_address = json.dumps(grouped['EletronicAddress'])
            TSPInformationURI = json.dumps(grouped['TSPInformationURI'])

            insert_query = """
                                UPDATE trust_service_providers 
                                SET name = %s, postal_address = %s, trade_name = %s, EletronicAddress = %s, TSPInformationURI = %s
                                WHERE tsp_id = %s
                            """
            cursor.execute(insert_query, (name, postal_address, trade_name, electronic_address, TSPInformationURI, tsp_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSP successfully updated: {tsp_id}", extra=extra)

            print(f"TSP successfully updated: {tsp_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_data_service_edit(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT ServiceName, SchemeServiceDefinitionURI
                FROM trust_services
                WHERE service_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchone()

            if result:
                column_names = [desc[0] for desc in cursor.description]
                user_info = dict(zip(column_names, result))
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information: {id}", extra=extra)
                print(f"Getting SERVICE information: {id}")
                
                return user_info
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information: {id}", extra=extra)
                print(f"Error Getting TSL information: {id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching USER info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def edit_service(grouped, service_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()
            ServiceName = json.dumps(grouped['ServiceName'])
            SchemeServiceDefinitionURI = json.dumps(grouped['SchemeServiceDefinitionURI'])

            insert_query = """
                                UPDATE trust_services 
                                SET ServiceName = %s, SchemeServiceDefinitionURI = %s
                                WHERE service_id = %s
                            """
            cursor.execute(insert_query, (ServiceName, SchemeServiceDefinitionURI, service_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"SERVICE successfully updated: {service_id}", extra=extra)
            print(f"service successfully updated: {service_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()
            
def get_service_update(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT * 
                FROM trust_services 
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchall()
            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information, for the OPERATOR: {id}", extra=extra)
                print(f"Getting SERVICE information, for the OPERATOR: {id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information, for the OPERATOR: {id}", extra=extra)
                print(f"Error Getting SERVICE information, for the TSL: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def update_service(service_id, tsp_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE trust_services 
                                SET tsp_id = %s
                                WHERE service_id = %s
                            """
            cursor.execute(insert_query, (tsp_id, service_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"SERVICE successfully updated: {service_id}", extra=extra)

            print(f"service successfully updated: {service_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error inserting user: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_tsp_update(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT * 
                FROM trust_service_providers 
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchall()
            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information, for the OPERATOR: {id}", extra=extra)
                print(f"Getting TSP information, for the OPERATOR: {id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the OPERATOR: {id}", extra=extra)
                print(f"Error Getting TSL information, for the OPERATOR: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()
            
def update_tsp(tsp_id, tsl_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE trust_service_providers 
                                SET tsl_id = %s
                                WHERE tsp_id = %s
                            """
            cursor.execute(insert_query, (tsl_id, tsp_id))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"TSP successfully updated: {tsp_id}", extra=extra)

            print(f"TSP successfully updated: {tsp_id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        print(f"Error updating user: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()
               
def get_tsl_xml(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT SchemeName_lang, tsl_id
                FROM trusted_lists 
                WHERE operator_id = %s
            """
            
            cursor.execute(select_query, (id,))
            
            result = cursor.fetchall()
            if result:
                extra = {'code': log_id} 
                logger.error(f"Getting TSL information, for the OPERATOR: {id}", extra=extra)
                print(f"Getting TSL information, for the OPERATOR: {id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information, for the OPERATOR: {id}", extra=extra)
                print(f"Error Getting TSL information, for the TSL: {id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching tsl: {e}", extra=extra)
        print(f"Error fetching tsl: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_tsp_xml(tsl_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trust_service_providers
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (tsl_id,))
            
            result = cursor.fetchall()

            if result:
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information, for the TSL: {tsl_id}", extra=extra)
                print(f"Getting TSP information, for the TSL: {tsl_id}")
                
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the TSL: {tsl_id}", extra=extra)
                print(f"Error Getting TSP information, for the TSL: {tsl_id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSP info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()
       
def get_service_xml(tsp_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trust_services
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (tsp_id,))
            
            result = cursor.fetchall()

            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information, for the TSP: {tsp_id}", extra=extra)
                print(f"Getting SERVICE information, for the TSP: {tsp_id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information, for the TSP: {tsp_id}", extra=extra)
                print(f"Erro Getting TSL information, for the TSL: {tsp_id}")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching Service info: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def check_tsp(tsl_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT tsp_id
                FROM trust_service_providers
                WHERE tsl_id = %s
            """
            
            cursor.execute(select_query, (tsl_id,))
            
            result = cursor.fetchall()

            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSP information, for the TSL: {tsl_id}", extra=extra)
                print(f"Getting TSP information, for the TSL: {tsl_id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSP information, for the TSL: {tsl_id}", extra=extra)
                print(f"Error Getting TSP information, for the TSL: {tsl_id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()


def check_service(tsp_id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT service_id
                FROM trust_services
                WHERE tsp_id = %s
            """
            
            cursor.execute(select_query, (tsp_id,))
            
            result = cursor.fetchall()

            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting SERVICE information, for the TSP: {tsp_id}", extra=extra)
                print(f"Getting SERVICE information, for the TSP: {tsp_id}")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting SERVICE information, for the TSP: {tsp_id}", extra=extra)
                print(f"Erro Getting SERVICE information, for the TSP: {tsp_id}")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching TSP: {e}", extra=extra)
        print(f"Error fetching TSP: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def update_lotl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE trusted_lists 
                                SET lotl = 1
                                WHERE tsl_id = %s
                            """
            cursor.execute(insert_query, (id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"Lotl successfully updated: {id}", extra=extra)

            print(f"Lotl successfully updated: {id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error update_lotl: {e}", extra=extra)
        print(f"Error update_lotl: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def update_not_selected_lotl(id, log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            insert_query = """
                                UPDATE trusted_lists 
                                SET lotl = 0
                                WHERE tsl_id = %s
                            """
            cursor.execute(insert_query, (id,))
            
            connection.commit()
            
            extra = {'code': log_id} 
            logger.info(f"Lotl successfully updated: {id}", extra=extra)

            print(f"Lotl successfully updated: {id}")
            return cursor.lastrowid

    except pymysql.MySQLError as e:
        extra = {'code': log_id} 
        logger.error(f"Error update_lotl: {e}", extra=extra)
        print(f"Error update_lotl: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_tsls_ids(log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor()

            select_query = """
                SELECT tsl_id
                FROM trusted_lists
            """
            
            cursor.execute(select_query)
            result = cursor.fetchall()
            
            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSL information", extra=extra)
                print(f"Getting TSL information")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information", extra=extra)
                print(f"Error Getting TSL information")
                return None
        else:
            return None

    except pymysql.MySQLError as e:
        extra = {'code': log_id}
        logger.error(f"Error checking user: {e}", extra=extra)
        print(f"Error checking user: {e}")
        return None
    finally:
        if connection:
            cursor.close()
            connection.close()

import pymysql

def get_tsl_loft(log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trusted_lists
                WHERE lotl = 1
            """
            
            cursor.execute(select_query)
            result = cursor.fetchall()

            if result:
                extra = {'code': log_id} 
                logger.error("Getting TSL information in LOTL", extra=extra)
                print("Getting TSL information in LOTL")
                
                return result
            else:
                extra = {'code': log_id} 
                logger.error("Error Getting TSL information in LOTL", extra=extra)
                print("Error Getting TSL information in LOTL")
                return None

    except pymysql.MySQLError as e:
        print(f"Error fetching TSL info in LOTL: {e}")
        extra = {'code': log_id} 
        logger.error(f"Error processing the form: {e}", extra=extra)

        return None
    finally:
        if connection:
            cursor.close()
            connection.close()


def get_lotl_tsl(log_id):
    try:
        connection = conn()
        if connection:
            cursor = connection.cursor(cursor=pymysql.cursors.DictCursor)

            select_query = """
                SELECT *
                FROM trusted_lists
            """
            
            cursor.execute(select_query)
            
            result = cursor.fetchall()
            if result:
                
                extra = {'code': log_id} 
                logger.error(f"Getting TSL information", extra=extra)
                print(f"Getting TSL information")
                return result
            else:
                extra = {'code': log_id} 
                logger.error(f"Error Getting TSL information", extra=extra)
                print(f"Error Getting TSL information")
                return None

    except pymysql.MySQLError as e:
        
        extra = {'code': log_id} 
        logger.error(f"Error fetching user_id: {e}", extra=extra)
        print(f"Error fetching user_id: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()
