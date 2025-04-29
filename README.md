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
     + Add information in new language: Add new info to scheme operator data;
     + Edit Information: Edit scheme Operator data;
     + Manage TSL: List all Trusted Lists associated to user;
    
  3. When the user accesses the option List TSL, they will be presented with a list of all the TSLs associated with them. It contains the following options:
     + Create a new Trusted Service List: Create Trusted List;
     + Edit TSL: Update Trusted Lists data that are associated to user;
     + Add new language Info: To add new information to the data in different languages;
     + Add Trust Service Providers: Select Trust Service Providers to be associated with the TSL.
     + Generate and sign Trusted Service List: Generate the XML of the selected TSL (To be able to generate the xml and sign it, the user must associate at least one existing TSP in the system);
       
       
  ### 4. Menu - Trust Service Provider user

  1.  Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
      + Manage TSP: List all Trust Service Providers associated to user;
      + Manage Trust Services: List all Trust Services created by user;
    
  2.  When the user accesses the option List TSPs, they will be presented with a list of all the TSPs associated with them. It contains the following options:
      +  Create a new Trust Service Provider: Adds a New Trust Service Provider;
      +  Edit Trust Service Provider: Edit Trust Service Providers associated to user;
      +  Add new language Info: To add new information to the data in different language;
      +  Add Services: Select services to be associated with the TSP.
    
        
  After creating a TSP, the user needs to create a service and associate it with it or associate an existing service.

  3. When the user accesses the option List Trust Services, they will be presented with a list of all the Trust Services associated with them. It contains the following options:
      +  Create a new Service: Adds a New Service;
      +  Edit Trust Service: Edit Trust Services associated to user;
      +  Add new language Info: To add new information to the data in different language;  

  4. Other options are currentelly under development:
     + Remove TSP: Remove Trust Service Providers Associated to user;
     + Remove Service: Remove Services created by user;
     + Service Status History: List all Service Status History;
     + Export Audit Log: Export Audit Log;

  ### 5. Menu - Admin user
  The Admin user is the only user who can create a single LoTL (List of Trusted Lists).
  
  1. Once the user has logged in with the EUDI Wallet, they are presented with a menu. It contains the following options:
     + Add information in new language: Add new info to scheme operator data;
     + Edit Information: Edit scheme Operator data;
     + Create LoTL: List of all the trust lists that the admin can add to LoTL and generate LoTL xml (To create a LoTL, the user must associate at least one existing TSL in the system);
     + LoTL Information: Manage Information related to LoTL;
       
  2. When the user accesses the option Create LoTL, they will be presented with a list of all the TSLs in the system. It contains the following options:
     + Update selected Trusted Service Lists: Add Trusted Lists with the checkbox checked in the Actions column ;
     + Generate and sign LoTL;
       
  3. When the user accesses the option LoTL Information, they will be presented with the following options:
     +  Add new language Info: To add new information to the data in different language;
     +  Edit Lotl Information: Update existing LoTL-related data; 
     
