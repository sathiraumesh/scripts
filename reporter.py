
class Reporter:

    def generate_report_text(self, allowed_licenses, not_allowed_licenses):
        final_not_allowed_licenses = set()
        for item in not_allowed_licenses:
            final_not_allowed_licenses.add(item['license'])
        final_info = []
        for license in final_not_allowed_licenses :
            scan_result = True
            info = []
            for not_allowed_license in not_allowed_licenses:
                if(license==not_allowed_license['license']):
                    if(scan_result and not isinstance(not_allowed_license['conclusion'], list)):
                        scan_result =False
                        info.append({'path':not_allowed_license['path'],'result':'not-okay','conclusion':not_allowed_license['conclusion']})
                    elif(not scan_result and not isinstance(not_allowed_license['conclusion'], list)):
                        info.append({'path': not_allowed_license['path'], 'result': 'not-okay',
                                     'conclusion': not_allowed_license['conclusion']})
                    else:
                        info.append({'path': not_allowed_license['path'], 'result': 'okay identified by user',
                                     'conclusion': not_allowed_license['conclusion']})

            final_info.append({'license':license,'paths':info,'scan-result':scan_result})
        print(final_info)
        file = open("license-report.txt", "w")
        file.write("{:<40} {:<20} {:<20} ".format('License', 'Recommendation', 'Scan Results', ))
        file.write("\n")

        for license in allowed_licenses:
            if (license != 'No_license_found' and not(str(license).lower().__contains__('possibility'))):
                file.write("{:<40} {:<20} {:<20} ".format(f'{license}', 'Allowed', 'ok', ))
                file.write("\n")

        for item in final_info:
            if (license != 'No_license_found' and item["scan-result"] ):
                file.write("{:<40} {:<20} {:<20} ".format(f'{item["license"]}', 'Not Allowed', 'ok'))
            elif(license != 'No_license_found' and not item["scan-result"]):
                file.write("{:<40} {:<20} {:<20} ".format(f'{item["license"]}', 'Not Allowed', 'not ok'))
            file.write("\n")
        file.write("\n")
        file.write("\n")
        file.write("\n")
        file.write("{:<40} {:<100} {:<20}  ".format('License', 'Location', 'Reason' ))
        file.write("\n")

        for item in final_info:
            if (item["license"]!= 'No_license_found'):
                for path_info in item['paths']:
                    file.write("{:<40} {:<150} {:<20}".format(f'{item["license"]}', f'{path_info["path"]}', f'{path_info["result"]}'))
                    file.write("\n")
        file.close()
