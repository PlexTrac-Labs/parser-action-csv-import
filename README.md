# parser-action-csv-import
This script is meant to help manage Parser Actions in platform. It utilizes the API to update or create new parser actions based on data provided from a CSV file. This allows makes updates in bulk and better hanlding of modifications needing to be made to parser actions.

In platform you're not able to direct import Parser Actions, you can only import scan files. This script "imports" parser action by sending a create or update request.

The script is meant to work in tandem with the parser-action-csv-export script. The schema of the CSV produced when exporting, is the expected schema to import in this script.

The table below gives some details about different properties of a parser action stored in Plextrac. It also shows which data in the CSV is used when creating or updating a parser action.
|  | plugin_id | title | action | severity | original_severity | description | last_updated_at | writeup_id | writeup_title | writeup_abbreviation | writeup_repository_id |
|-|-|-|-|-|-|-|-|-|-|-|-|
| Details | ID cannot be changed after creation | title cannot be changed after creation | one of ["PASS_THROUGH", "IGNORE", "DEFAULT", "LINK"] | one of ["Critical", "High", "Medium", "Low", "Informational"] | original severity cannot be set. severity at time of creation is used | description cannot be changed after creation | parser action creation does not add a updated at timestamp |  |  |  |  |
| Create | created | created | created | created | - | created | - | created | created | - | - |
| Update | - | - | updated | updated | - | - | - | updated | updated | - | - |

# Requirements
- [Python 3+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [pipenv](https://pipenv.pypa.io/en/latest/install/)

# Installing
After installing Python, pip, and pipenv, run the following commands to setup the Python virtual environment.
```bash
git clone this_repo
cd path/to/cloned/repo
pipenv install
```

# Setup
After setting up the Python environment the script will run in, you will need to setup a few things to configure the script before running.

## Credentials
In the `config.yaml` file you should add the full URL to your instance of Plextrac.

The config also can store your username and password. Plextrac authentication lasts for 15 mins before requiring you to re-authenticate. The script is set up to do this automatically through the authentication handler. If these 3 values are set in the config, and MFA is not enabled for the user, the script will take those values and authenticate automatically, both initially and every 15 mins. If any value is not saved in the config, you will be prompted when the script is run and during re-authentication.

# Usage
After setting everything up you can run the script with the following command. You should run the command from the folder where you cloned the repo.
```bash
pipenv run python main.py
```
You can also add values to the `config.yaml` file to simplify providing the script with custom parameters needed to run.

## Required Information
The following values can either be added to the `config.yaml` file or entered when prompted for when the script is run.
- PlexTrac Top Level Domain e.g. https://yourapp.plextrac.com
- Username
- Password
- Parser ID
- CSV file path

The parser ID determines which parser you want to update or create parser actions in. The list for all available parsers is:
- acunetix
- burp
- burphtml
- checkmarx
- coreimpact
- custom
- hclappscan
- horizon
- invicti
- nessus
- netsparker
- nexpose
- nipper
- nmap
- nodeware
- nodezero
- offlinecsv
- openvas
- owaspzap
- pentera
- ptrac
- qualys
- rapidfire
- scythe
- veracode

## Script Execution Flow
- Verifies the parser ID is a valid ID of an existing Parser in platform
- Load and parses the parser actions from the CSV
- Loads existing parser action for specified parser from instance
- Gets list of update to make and new parser actions to create
- Update parser actions
- Creates any new parser actions
