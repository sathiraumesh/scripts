import json
from server import Server


server_config_file = open('server.config.json','rb');
server_config = json.load(server_config_file)
server = Server(server_config);
access_token =  server.generate_access_token()
upload_id = server.upload_asset(access_token,'/Users/sathiraumesh/Downloads/build2/libs/test.jar')
server.schedule_scanners(access_token,upload_id)
results = server.get_license_findings(access_token,upload_id)


def get_formatted_licenses(findings):
    findings_list = findings
    formatted_finding_list = []

    for item in findings_list:
        licenses = item['findings']['scanner']
        path = item['filePath']
        if (isinstance(licenses, list)):

            if (len(licenses) == 1 and licenses[0] == 'No_license_found'):
                print("")
            else:
                formatted_finding_list.append({'path': path, 'licenses': licenses})

    return formatted_finding_list


def get_not_allowed_licenses_path(formatted_finding_list):
    n_licens = ['gpl', 'agpl']
    rules = "classpath-exception"
    not_allowed_licenses = []
    for item in formatted_finding_list:
        licenses = item['licenses']
        path = item['path']
        if (len(licenses) == 1):
            license = str(licenses[0])
            for not_allowed_license in n_licens:
                if (license.lower().startswith(not_allowed_license)):
                    not_allowed_licenses.append({'path': path, 'license': license})
                    break

    for item in formatted_finding_list:
        licenses = item['licenses']
        path = item['path']
        is_not_allowed_license = False
        is_rule = False
        multiple_license = []
        if (len(licenses) > 1):
            for not_allowed_license in n_licens:
                for license in licenses:
                    if (license.lower().startswith(not_allowed_license)):
                        is_not_allowed_license = True
                        multiple_license.append(license)
                    elif (license.lower().startswith(rules)):
                        is_rule = True
        if (is_not_allowed_license == True and is_rule == False):
            for license in multiple_license:
                not_allowed_licenses.append({'path': path, 'license': license})
    return not_allowed_licenses


def get_allowed_licenses(formatted_finding_list):
    unique_licenses = set()
    allowed_licenses = []
    unclassified_licenses = []
    n_licenes = ['gpl', 'agpl']
    a_licenses = [
        {'license': 'MIT', 'op': 'match'},
        {'license': 'Apache', 'op': 'match'},
        {'license': 'Public-domain', 'op': 'match'},
        {'license': 'BSD', 'op': 'match'},
        {'license': 'CC-BY-2.5', 'op': 'equal'},
        {'license': 'EDL', 'op': 'match'},
        {'license': 'EPL', 'op': 'match'},
        {'license': 'IPL', 'op': 'match'},
        {'license': 'W3C', 'op': 'match'},
        {'license': 'OpenSSL', 'op': 'match'},
        {'license': 'Classpath-exception', 'op': 'contain'},
        {'license': 'CDDL', 'op': 'match'},
        {'license': 'LGPL', 'op': 'match'},
        {'license': 'Flora', 'op': 'match'},
        {'license': 'MPL', 'op': 'match'},
        {'license': 'Dual-license', 'op': 'match'},
        {'license': 'ANTLR-PD', 'op': 'match'},
        {'license': 'JSON', 'op': 'match'},
        {'license': 'Unlicense', 'op': 'match'}
    ]

    for item in formatted_finding_list:
        licenses = item['licenses']
        for license in licenses:
            unique_licenses.add(license)

    for unique_license in unique_licenses:
        is_unclassified_license = True
        for a_license in a_licenses:
            license = str(a_license['license'])
            operation = a_license['op']
            if (operation == 'match' and unique_license.lower().startswith(license.lower())):
                allowed_licenses.append(unique_license)
                is_unclassified_license = False
            elif (operation == 'equal' and unique_license.lower().__eq__(license.lower())):
                allowed_licenses.append(unique_license)
                is_unclassified_license = False
            elif (operation == 'contain' and (license.lower() in unique_license.lower())):
                allowed_licenses.append(unique_license)
                is_unclassified_license = False
        if (is_unclassified_license):
            unclassified_licenses.append(unique_license)

    print(allowed_licenses)
    temp_not_allowed_licenses = []
    for n_license in n_licenes:
        for item in unclassified_licenses:
            license = str(item)
            if (license.lower().startswith(n_license.lower())):
                temp_not_allowed_licenses.append(license)

    for license in temp_not_allowed_licenses :
        unclassified_licenses.remove(license)
    print(unclassified_licenses)

    return {'unclassified': unclassified_licenses, 'allowed': allowed_licenses}
    # for temp_license in temp_license_list:
    #     for unique_license in temp_license :
    #         unique_licenses.add(unique_license)


def generate_report(allowed_licenses, not_allowed_licenses, unclassified_licenses):
    final_not_allowed_licenses = set()
    for item in not_allowed_licenses :
        final_not_allowed_licenses.add(item['license'])

    my_file = open("test_file.txt", "w")
    my_file.write("{:<40} {:<20} {:<20} ".format('License', 'Recommendation', 'Scan Results \n', ))
    for license in allowed_licenses:
        my_file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'Allowed', 'ok\n' ))

    for license in final_not_allowed_licenses :
        my_file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'Not Allowed', '--\n' ))

    for license in unclassified_licenses:
        if (license.lower()!='No_license_found'.lower()):
            my_file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'unclassified', '--\n'))

    my_file.write("\n")
    my_file.write("\n")
    my_file.write("\n")
    my_file.write("{:<40} {:<100} {:<20} ".format('License', 'Location', 'Reason', ))
    my_file.write("\n")
    for item in not_allowed_licenses:
        my_file.write("{:<40} {:<100} {:<20} ".format(f'{item["license"]}', f'{item["path"]}', 'ok', ))
        my_file.write("\n")



# test1 = [{'path': 'path', 'licenses': ['Apache-2.0']}, {'path': 'pa', 'licenses': ['GPL-2.0']},
#          {'path': 'path', 'licenses': ['AGPL-2.0']}]
# test2 = [{'path': 'path', 'licenses': ['Apache-2.0']}, {'path': 'path', 'licenses': ['MIT']}]
# test3 = [{'path': 'path', 'licenses': ['Apache-2.0']}, {'path': 'pasdasd', 'licenses': ['MIT', 'GPL', 'GPL-2.0']},
#          {'path': 'path', 'licenses': ['GPL', 'MIT', 'AGPL']},
#          {'path': 'path', 'licenses': ['GPL', "classpath-exception"]}]
formatted_finding_list = get_formatted_licenses(results)
not_allowed_licenses = get_not_allowed_licenses_path(formatted_finding_list)
print(not_allowed_licenses)
allowed = get_allowed_licenses(formatted_finding_list)
generate_report(allowed['allowed'], not_allowed_licenses,allowed['unclassified'])

