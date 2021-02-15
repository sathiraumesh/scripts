import json
from server import Server
from analyser import Analyser
from reporter import Reporter


server_config_file = open('server.config.json','rb')
server_config = json.load(server_config_file)
server = Server(server_config)
analyser = Analyser()
reporter = Reporter()
#
# access_token =  server.generate_access_token()
# upload_id = server.upload_asset(access_token,'/Users/sathiraumesh/Downloads/oms-core-master/out/oms-core.jar')
# server.schedule_scanners(access_token,upload_id)
# results = server.get_license_findings(access_token,upload_id)
#
# formatted_findings= analyser.get_formatted_licenses(results)
# licenses = analyser.get_allowed_not_allowed_licenses(formatted_findings)
# allowed_licenses = licenses['allowed-licenses']
# not_allowed_licenses = licenses ['not-allowed-licenses']
# not_allowed_licenses_info=analyser.get_decisions_on_not_allowed_licenses(not_allowed_licenses=not_allowed_licenses,formatted_licenses=formatted_findings)


# def generate_report(allowed_licenses, not_allowed_licenses, ):
#     final_not_allowed_licenses = set()
#     for item in not_allowed_licenses :
#         final_not_allowed_licenses.add(item['license'])
#
#     my_file = open("license-report.txt", "w")
#     my_file.write("{:<40} {:<20} {:<20} ".format('License', 'Recommendation', 'Scan Results', ))
#     my_file.write("\n")
#     for license in allowed_licenses:
#         my_file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'Allowed', 'ok', ))
#         my_file.write("\n")
#
#     for license in final_not_allowed_licenses:
#         my_file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'Not Allowed', '--'))
#         my_file.write("\n")
#
#     my_file.write("\n")
#     my_file.write("\n")
#     my_file.write("\n")
#     my_file.write("{:<40} {:<100} {:<20} ".format('License', 'Location', 'Reason', ))
#     my_file.write("\n")
#     for item in not_allowed_licenses:
#         my_file.write("{:<40} {:<100} {:<20} ".format(f'{item["license"]}', f'{item["path"]}', '--', ))
#         my_file.write("\n")
#     my_file.close()



test1 = []
test2 = [{'path': 'path', 'licenses': ['Apache-2.0'],'conclusion':'None'}, {'path': 'path', 'licenses': ['MIT'],'conclusion':'None'}]
test3 = [{'path': 'path', 'licenses': ['Apache-2.0'],'conclusion':'None'}, {'path': 'pasdasd', 'licenses': ['MIT', 'GPL', 'GPL-2.0'],'conclusion':['GPL']},
         {'path': 'path', 'licenses': ['GPL', 'MIT', 'AGPL'],'conclusion':'None'},
         {'path': 'path', 'licenses': ['GPL', "classpath-exception"],'conclusion':'None'}]

# print(not_allowed_licenses)
#
licenses = analyser.get_allowed_not_allowed_licenses(test1)
allowed_licenses = licenses['allowed-licenses']
not_allowed_licenses = licenses ['not-allowed-licenses']
print(allowed_licenses)
print(not_allowed_licenses)
print(allowed_licenses)
print(not_allowed_licenses)
not_allowed_licenses_info=analyser.get_decisions_on_not_allowed_licenses(not_allowed_licenses=not_allowed_licenses,formatted_licenses=test1)
print(not_allowed_licenses_info)
reporter.generate_report_text(allowed_licenses, not_allowed_licenses_info)

print('\033[32m'+"sd")

