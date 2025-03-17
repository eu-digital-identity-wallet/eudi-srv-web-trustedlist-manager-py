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

  There are two ways to use it:

  + With 1 user -> 1 user has access to both menus.
  + With 2 users (TSL user and TSP user) -> each user only has access to their corresponding menu.

  To switch between these two modes, simply go to the file "config.py" inside "app_config", and look for the "two_operators" option.
  
  + "False" -> 1 user
  + "True"  -> 2 users
  + Note: By default, the option is set to "False".

  ### 3. Menu - Scheme Operator Trusted List user

  1. Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
     + New Info Lang: Add new info to scheme operator data;
     + Edit Info: Edit scheme Operator data;
     + List TSL: List all Trusted Lists associated to user;
    
  3. When the user accesses the option List TSL, they will be presented with a list of all the TSLs associated with them. It contains the following options:
     + Create TSL: Create Trusted List;
     + Update TSL: Update Trusted Lists data that are associated to user;
     + Add new language Info: To add new information to the data in different languages;
     + Add Trust Service Providers: Select Trust Service Providers to be associated with the TSL.
     + Generate XML: Generate the XML of the selected TSL;
     
  2. Other options are currentelly under development:
     + View History: View past updates of Trusted List;
     + Export Audit Log: Export Audit Log;
     + Operator Profile: Operator data;
     + Security Settings: Security Settings;
     + Permissions Management: Permissions Management;
       
  ### 4. Menu - Trust Service Provider user

  1.  Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
      + List TSPs: List all Trust Service Providers associated to user;
      + List Trust Services: List all Trust Services created by user;
    
  2.  When the user accesses the option List TSPs, they will be presented with a list of all the TSPs associated with them. It contains the following options:
      +  Add New TSP: Adds a New Trust Service Provider;
      +  Edit TSP: Edit Trust Service Providers associated to user;
      +  Add new language Info: To add new information to the data in different language;
      +  Add Services: Select services to be associated with the TSP.

  3. When the user accesses the option List Trust Services, they will be presented with a list of all the Trust Services associated with them. It contains the following options:
      +  Add New Service: Adds a New Service;
      +  Edit Trust Service: Edit Trust Services associated to user;
      +  Add new language Info: To add new information to the data in different language;  

  4. Other options are currentelly under development:
     + Remove TSP: Remove Trust Service Providers Associated to user;
     + Remove Service: Remove Services created by user;
     + Service Status History: List all Service Status History;
     + View History: View past updates of Trust Service Providers associated to user;
     + Export Audit Log: Export Audit Log;
     + Operator Profile: Operator data;
     + Security Settings: Security Settings;
     + Permissions Management: Permissions Management;

       
  ### 5. Menu - Admin user
  The Admin user is the only user who can create a single LoTL (List of Trusted Lists).
  
  1. Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
     + New Info Lang: Add new info to LoTL;
     + Edit Info: Edit LoTL;
     + Generate XML: Generate LoTL xml;
     + List TSL: List of all the trust lists that the admin can add to LoTL;
       
  2. When the user accesses the option List TSL, they will be presented with a list of all the TSLs. It contains the following options:
     + Add selected Trusted Lists: Add Trusted Lists with the checkbox checked in the Actions column ;
     
