# eudi-srv-web-trustedlist-manager-py

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Overview


## Installation
1. Enter the folder

  ```shell
  cd udi-srv-web-trustedlist-manager-py
  ```

2. Create .venv to install flask and other libraries

  Windows:
  
  ```shell
  python -m venv .venv 
  ```
  
  Linux:

  ```shell
  python3 -m venv .venv
  ```

3. Activate the environment

  windows:
    
  ```shell
  . .venv\Scripts\Activate
  ```
    
  Linux:
  
  ```shell
  . .venv/bin/activate
  ```
    
  4. Install the necessary libraries to run the code

  ```shell
  pip install -r app/requirements.txt
  ```

  5. Run the Project
  ```shell
  flask --app app run
  ```

## Run

  ### 1. Database
  1. Change app/app_config/database.py to your DB settings

  2. Populate "countries" Table with at least one country. Recommended: 
  
  ```shell     
INSERT INTO countries (country_id, country_code, country_name) VALUES (1, 'FC', 'Fake Country');
```
  ### 2. Initial Page

  Initial Page of the Trusted Lists Registration Service (<http://127.0.0.1:5000/> or <http://localhost:5000/>) :
  + AUTH: <http://localhost:5000/authentication>

  ### 3. Menu - Scheme Operator Trusted List user

  1. Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
     + XML: Generate Trusted List XML with user already created a Trusted List;
     + View Current TSL: View Trusted Lists associated to user;
     + Create TSL: Create Trusted List;
     + Update Existing TSL: Update Trusted Lists data that are associated to user;
     + Digitally sign the TSL: Inserts Xades Signature into Trusted List.
     
  2. Other options are currentelly under development:
     + Update History: View past updates of Trusted List;
     + Register New Update: Register Update of Trusted List;
     + Export Audit Log: Export Audit Log;
     + Operator Profile: Operator data;
     + Security Settings: Security Settings;
     + Permissions Management: Permissions Management;
       
  ### 4. Menu - Trust Service Provider user

  1.  Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
      +  Add New TSP: Adds a New Trust Service Provider;
      +  Add New Service: Adds a New Service;
  2. Other options are currentelly under development:
     + List TSPs: List all Trust Service Providers associated to user;
     + Edit/Remove TSP: Edit/Remove Trust Service Providers Associated to user;
     + List Trust Services: List all Trust Services created by user;
     + Edit/Remove Service: Edit/Remove Services created by user;
     + Service Status History: List all Service Status History;
     + Update History: View past updates of Trust Service Providers associated to user;
     + Register New Update: Register Update of Trust Service Providers associated to user;
     + Export Audit Log: Export Audit Log;
     + Operator Profile: Operator data;
     + Security Settings: Security Settings;
     + Permissions Management: Permissions Management;
