import json
from server import Server
from analyser import Analyser


server_config_file = open('server.config.json','rb')
server_config = json.load(server_config_file)
server = Server(server_config)
analyser = Analyser()

access_token =  server.generate_access_token()
upload_id = server.upload_asset(access_token,'/Users/sathiraumesh/Downloads/build2/libs/test.jar')
server.schedule_scanners(access_token,upload_id)
results = server.get_license_findings(access_token,upload_id)

formatted_findings= analyser.get_formatted_licenses(results)
licenses = analyser.get_allowed_not_allowed_licenses(formatted_findings)
print(licenses['allowed-licenses'])

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
# formatted_finding_list = get_formatted_licenses(results)
# not_allowed_licenses = get_not_allowed_licenses_path(formatted_finding_list)
# print(not_allowed_licenses)
# allowed = get_allowed_licenses(formatted_finding_list)
# generate_report(allowed['allowed'], not_allowed_licenses,allowed['unclassified'])

