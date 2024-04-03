import yaml
import csv
from typing import List
from copy import deepcopy

import settings
import utils.log_handler as logger
log = logger.log
from utils.auth_handler import Auth
import utils.input_utils as input
import api


def handle_load_csv_data_verify(path, headers) -> List[list]:
    """
    takes a filepath to a csv, and a list of expected headers and returned the csv data if the headers match
    used as basic error checking that we have the correct csv
    """
    csv = input.load_csv_data("Enter file path to CSV data to import", csv_file_path=path)

    if csv.headers != headers:
        log.exception(f'CSV headers read from file\n{csv.headers}')
        log.exception(f'Expected headers\n{headers}')
        log.exception(f'Exiting...')
        exit()
    if len(csv.data) < 1:
        log.exception(f'No data in loaded csv file. Exiting...')
        exit()

    log.success(f'Loaded csv data')
    return csv.data


def verified_parser_id(parser_id: str) -> str:
    """
    Checks if the given the parser ID value from the config.yaml file matches the ID of an existing
    plugin already imported in Plextrac. If the plugin exists in platform, returns the verified
    parser ID

    Prompts the user to choose a parser ID if one is not supplied in the config, or if the supplied
    value doesn't match an exisiting plugin.
    """
    log.info(f'Verifing parser exists in Plextrac. Loading parsers from instance...')
    instance_parser_list = []
    try:
        # region - expceted response
        # {
        #     "status": "success",
        #     "parsers": [
        #         {
        #             "name": "Acunetix",
        #             "id": "acunetix"
        #         },
        #         {
        #             "name": "Burp",
        #             "id": "burp"
        #         },
        #         {
        #             "name": "Nessus",
        #             "id": "nessus"
        #         },
        #         {
        #             "name": "Nipper",
        #             "id": "nipper"
        #         },
        #         {
        #             "name": "CSV",
        #             "id": "offlinecsv"
        #         },
        #         {
        #             "name": "Qualys",
        #             "id": "qualys"
        #         }
        #     ]
        # }
        # endregion
        response = api.parser_actions.get_tenant_parsers(auth.base_url, auth.get_auth_headers(), auth.tenant_id)
        if len(response.json.get("parsers", [])) < 1:
            log.error(f'Plextrac contains no existing parsers. Can only import parser actions to an existing parser. Exiting...')
            exit()
        instance_parser_list = response.json.get("parsers", [])
    except Exception as e:
        log.error(f'Could not load parsers from instance.\n{e}')
        exit()

    # no parser ID in config
    if parser_id == "":
        return pick_parser(instance_parser_list)
    # valid parser ID in config
    parser_ids = list(map(lambda x: x['id'], instance_parser_list))
    if parser_id in parser_ids:
        log.success(f'Found \'{parser_id}\' parser is valid parser in Plextrac instance')
        return parser_id
    # invalid parser ID in config
    user_input = input.user_options(f"Parser \'{parser_id}\' does not exist in platform. Do you want to pick a different parser", "Invalid option", ["y", "n"])
    if user_input == "y":
        return pick_parser(instance_parser_list)
    exit()


def pick_parser(parser_list) -> str:
    """
    Display the list of parsers in the instance to the user and prompts them to pick a parser.
    Returns the parser_id of the selected parser.
    """
    log.info(f'List of Parsers in tenant {auth.tenant_id}:')
    for index, parser in enumerate(parser_list):
        log.info(f'Index: {index+1}   Name: {parser.get("name")}')

    parser_index = input.user_list("CRITICALLY IMPORTANT: Please enter a parser index from the list above, for the parser you want to import the CSV of parser actions to.\nNOTE: Parser action CANNOT be deleted, make sure you select the right parser to import into.", "Index out of range.", len(parser_list))
    parser = parser_list[parser_index-1]
    parser_id = parser.get("id")
    parser_name = parser.get("name")
    log.info(f'Selected Parser: {parser_index} - {parser_name}')

    return parser_id


def parse_loaded_csv_of_parser_actions(loaded_csv) -> List[dict]:
    parser_actions = []
    for i, row in enumerate(loaded_csv):
        id = row[0]
        title = row[1]
        action = row[2]
        severity = row[3]
        description = row[5]
        writeup_id = row[7]
        writeup_label = row[8]

        if (id == "" or id == None) or (title == "" or title == None):
            log.exception(f'Row {i+2} in CSV has no \'id\' or \'title\', skipping row...')
            continue

        # action codes for Default, Ignore, Severity, and Link Writeup
        valid_actions = ["PASS_THROUGH", "IGNORE", "DEFAULT", "LINK"]
        if action not in valid_actions:
            log.exception(f'Could not use \'{action}\' as an action, must be one of {valid_actions}. Using \'Default\' as action...')
            action = "PASS_THROUGH"

        # parser_action obj will be modified later depending if it's the payload for a create or update request
        parser_action = {
            "id": id,
            "title": title,
            "description": description,
            "action": action,
            "severity": severity,
            "writeupID": writeup_id,
            "writeupLabel": writeup_label
        }

        parser_actions.append(parser_action)

    return parser_actions


def get_page_of_parser_actions(parser_id: str, page: int = 0, actions: list = [], total_actions: int = -1) -> None:
    """
    Handles traversing pagination results to create a list of all items.

    :param page: page to start on, for all results use 0, defaults to 0
    :type page: int, optional
    :param assets: the list passed in will be added to, acts as return, defaults to []
    :type assets: list, optional
    :param total_assets: used for recursion to know when all pages have been gathered, defaults to -1
    :type total_assets: int, optional
    """
    log.info(f'Load page {page} of parser actions...')
    offset = page*1000
    limit = 1000
    # region EXAMPLE schema of returned parser actions
        # {
        #     "id": "10028",
        #     "action": "LINK",
        #     "severity": "Medium",
        #     "writeupID": "101219",
        #     "log_trail": [
        #         {
        #             "updated_by": {
        #                 "user_id": 13338,
        #                 "name": {
        #                     "first": "Jordan",
        #                     "last": "Treasure"
        #                 }
        #             },
        #             "updated_at": 1701906483227,
        #             "action": "LINK",
        #             "severity": "Medium",
        #             "writeupID": "11407137"
        #         }
        #     ],
        #     "title": "DNS Server BIND version Directive Remote Version Detection",
        #     "description": "The remote host is running BIND or another DNS server that reports its version number when it receives a special request for the text 'version.bind' in the domain 'chaos'. \n\nThis version is not necessarily accurate and could even be forged, as some DNS servers send the information based on a configuration file.\n",
        #     "writeup": {
        #         "description": "Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. This behavior can be leveraged to facilitate phishing attacks against users of the application. The ability to use an authentic application URL, targeting the correct domain and with a valid SSL certificate (if SSL is used), lends credibility to the phishing attack because many users, even if they verify these features, will not notice the subsequent redirection to a different domain.\n",
        #         "doc_id": 101219,
        #         "doc_type": "template",
        #         "fields": {},
        #         "isDeleted": false,
        #         "id": "template_101219",
        #         "repositoryId": "cl6cg379h01km17lbeg713x1w",
        #         "recommendations": "If possible, applications should avoid incorporating user-controllable data into redirection targets. In many cases, this behavior can be avoided in two ways:\nRemove the redirection function from the application, and replace links to it with direct links to the relevant target URLs.\nMaintain a server-side list of all URLs that are permitted for redirection. Instead of passing the target URL as a parameter to the redirector, pass an index into this list.\n\nIf it is considered unavoidable for the redirection function to receive user-controllable input and incorporate this into the redirection target, one of the following measures should be used to minimize the risk of redirection attacks:\nThe application should use relative URLs in all of its redirects, and the redirection function should strictly validate that the URL received is a relative URL.\nThe application should use URLs relative to the web root for all of its redirects, and the redirection function should validate that the URL received starts with a slash character. It should then prepend http://yourdomainname.com to the URL before issuing the redirect.\nThe application should use absolute URLs for all of its redirects, and the redirection function should verify that the user-supplied URL begins with http://yourdomainname.com/ before issuing the redirect.\n\nStored open redirection vulnerabilities arise when the applicable input was submitted in an previous request and stored by the application. This is often more serious than reflected open redirection because an attacker might be able to place persistent input into the application which, when viewed by other users, causes their browser to invisibly redirect to a domain of the attacker's choice.\n",
        #         "references": "- Using Burp to Test for Open Redirections(https://support.portswigger.net/customer/portal/articles/1965733-Methodology_Testing%20for%20Open%20Redirections.html)\n- Fun With Redirects(https://www.owasp.org/images/b/b9/OWASP_Appsec_Research_2010_Redirects_XSLJ_by_Sirdarckcat_and_Thornmaker.pdf)\n\nCWE-601: URL Redirection to Untrusted Site ('Open Redirect')\n",
        #         "severity": "Medium",
        #         "source": "Burp",
        #         "tenantId": 0,
        #         "title": "Open redirection (stored)",
        #         "updatedAt": 1701714762104,
        #         "writeupAbbreviation": "DEF-1"
        #     },
        #     "original_severity": "Informational",
        #     "writeupLabel": "Open redirection (stored)"
        # }
    # endregion
    try:
        response = api.parser_actions.get_tenant_parser_actions(auth.base_url, auth.get_auth_headers(), auth.tenant_id, parser_id, limit, offset)
    except Exception as e:
        log.critical(f'Could not retrieve parser actions from instance. Exiting...')
        exit()
        
    total_actions = int(response.json['actions']['total_items'])
    if len(response.json['actions']['actions']) > 0:
        actions += deepcopy(response.json['actions']['actions'])
    
    if len(actions) < total_actions:
        return get_page_of_parser_actions(parser_id, page+1, actions, total_actions)
    
    return None


def import_parser_actions(parser_id, parser_actions:List[dict], auth: Auth):
    # need to know which parser actions already exist in platform and need to be updated vs new ones that need to be created
    existing_parser_actions_from_instance = []
    get_page_of_parser_actions(parser_id, actions=existing_parser_actions_from_instance)
    log.success(f'Loaded {len(existing_parser_actions_from_instance)} parser action(s) from instance')
    existing_parser_action_ids = list(map(lambda x:x['id'], existing_parser_actions_from_instance))

    parser_actions_to_create = []
    parser_actions_to_update = []
    for parser_action in parser_actions:
        if parser_action['id'] in existing_parser_action_ids: # update parser action in platform
            # update parser action parsed from CSV, to properties required for update request 
            parser_action.pop("title", None)
            parser_action.pop("description", None)
            if parser_action['action'] != "DEFAULT":
                parser_action.pop("severity", None)
            if parser_action['action'] != "LINK":
                parser_action["writeupID"] = ""
                parser_action["writeupLabel"] = ""
            parser_actions_to_update.append(parser_action)
        else: # create new parser action in platform
            parser_actions_to_create.append(parser_action)
    log.info(f'Parser Actions to Update: {len(parser_actions_to_update)}')
    log.info(f'Parser Actions to Create: {len(parser_actions_to_create)}')
    # updating parser actions
    log.info(f'Bulk updating {len(parser_actions_to_update)} parser action(s)...')
    try:
        payload = {
            "actions": parser_actions_to_update
        }
        response = api.parser_actions.bulk_update_tenant_parser_actions(auth.base_url, auth.get_auth_headers(), auth.tenant_id, parser_id, payload)
        if response.has_json_response and response.json.get("status") == "success":
            log.success(f'Updated {len(parser_actions_to_update)} parser actions')
        else:
            log.exception(f'Request to update parser actions did not return success message')
    except Exception as e:
        log.exception(f'Request failed to update parser actions')
    # creating parser actions
    log.info(f'Creating {len(parser_actions_to_create)} new parser action(s)...')
    for parser_action in parser_actions_to_create:
        try:
            payload = parser_action
            response = api.parser_actions.create_tenant_parser_action(auth.base_url, auth.get_auth_headers(), auth.tenant_id, parser_id, payload)
            if response.has_json_response and response.json.get("status") == "success":
                log.success(f'Created new parser action \'{parser_action["title"]}\'')
            else:
                log.exception(f'Create request did not return success message. Could not create parser action \'{parser_action["title"]}\'. Skipping...')
                continue
        except Exception as e:
            log.exception(f'Could not create parser action \'{parser_action["title"]}\'. Skipping...')
            continue


if __name__ == '__main__':
    for i in settings.script_info:
        print(i)

    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()

    csv_headers = ["plugin_id", "title", "action", "severity", "original_severity", "description", "last_updated_at", "writeup_id", "writeup_title", "writeup_abbreviation", "writeup_repository_id"]

    csv_file_path = ""
    if args.get('csv_file_path') != None and args.get('csv_file_path') != "":
        csv_file_path = args.get('csv_file_path')
        log.info(f'Using csv data file path \'{csv_file_path}\' from config...')

    parser_id = ""
    if args.get('parser_id') != None and args.get('parser_id') != "":
        parser_id = args.get('parser_id')
        log.info(f'Using parser \'{parser_id}\' from config...')
    
    # verify parser_id
    parser_id = verified_parser_id(parser_id)
    # load and parse CSV data
    loaded_csv_data = handle_load_csv_data_verify(csv_file_path, csv_headers)
    parser_actions_to_import = parse_loaded_csv_of_parser_actions(loaded_csv_data)
    if len(parser_actions_to_import) < 1:
        log.exception(f'Found no parser actions in CSV to import. Exiting...')
        exit()
    log.success(f'Parsed {len(parser_actions_to_import)} parser action(s) from CSV')

    # import parsed parser actions
    if input.continue_anyways(f'This will try to create or update {len(parser_actions_to_import)} \'{parser_id}\' parser action(s).\nNOTE: Once created, parser actions cannot be deleted.\nNOTE: If a parser action already exists it will be updated with the info from the CSV.\n'):
        import_parser_actions(parser_id, parser_actions_to_import, auth)
        log.info(f'Import Complete. Additional logs were added to {log.LOGS_FILE_PATH}')