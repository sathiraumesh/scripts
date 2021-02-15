import json
class Analyser:

    def __init__(self):
        self.name="sad"
    def filter_licensed_files(self,item):
        licenses = item['findings']['scanner']
        if( isinstance(licenses, list) and (not(len(licenses) == 1 and licenses[0] == 'No_license_found')) ):
            return True
        else:
            return False


    def get_formatted_licenses(self, findings):
        formatted_finding = []
        results = filter(self.filter_licensed_files,findings)

        for item in results:
            licenses = item['findings']['scanner']
            path = item['filePath']
            conclusion = item['findings']['conclusion']
            formatted_finding.append({'licenses':licenses,'path':path,'conclusion':conclusion})
        return formatted_finding

    def get_allowed_not_allowed_licenses(self, formatted_finding):
        unique_licenses = set()
        allowed_licenses = []
        not_allowed_licenses = []
        recommended_licenses_file = open('license.json', 'rb')
        data= json.load(recommended_licenses_file)
        recommended_licenses = data['allowed-license']

        for item in formatted_finding:
            licenses = item['licenses']
            for license in licenses:
                unique_licenses.add(license)

        for unique_license in unique_licenses:
            is_not_allowed_license = True
            for recommended_license in recommended_licenses:
                license = str( recommended_license['license'])
                operation =  recommended_license['op']
                if (operation == 'match' and unique_license.lower().startswith(license.lower())):
                    allowed_licenses.append(unique_license)
                    is_not_allowed_license = False
                elif (operation == 'equal' and unique_license.lower().__eq__(license.lower())):
                    allowed_licenses.append(unique_license)
                    is_not_allowed_license = False
                elif (operation == 'contain' and (license.lower() in unique_license.lower())):
                    allowed_licenses.append(unique_license)
                    is_not_allowed_license = False
            if (is_not_allowed_license):
                not_allowed_licenses.append(unique_license)
        return {'allowed-licenses':allowed_licenses,'not-allowed-licenses':not_allowed_licenses}


    def get_decisions_on_not_allowed_licenses(self, not_allowed_licenses, formatted_licenses):
        not_allowed_licenses_info=[]
        recommended_licenses_file = open('license.json', 'rb')
        data = json.load(recommended_licenses_file)
        rules = data['rules']

        for item in formatted_licenses:
            licenses = item['licenses']
            path = item['path']
            conclusion = item['conclusion']
            if (len(licenses) == 1):
                license = str(licenses[0])
                for not_allowed_license in not_allowed_licenses:
                    license_decision=(license.lower().__eq__(str(not_allowed_license).lower()))
                    if (license_decision):
                        not_allowed_licenses_info.append({'path': path, 'license': license,'conclusion':conclusion})
                        break
            elif(len(licenses) > 1):
                is_not_allowed_license = False
                is_rule = False
                multiple_license = []
                for not_allowed_license in not_allowed_licenses:
                    for license in licenses:
                        license_decision=license.lower().__eq__(str(not_allowed_license).lower())
                        if (license_decision):
                            is_not_allowed_license = True
                            multiple_license.append(license)
                        else:
                            for rule in rules:
                                rule_decision= license.lower().startswith(str(rule).lower())
                                if(rule_decision):
                                    is_rule = True
                                    break
                if (is_not_allowed_license == True and is_rule == False):
                    for license in multiple_license:
                        not_allowed_licenses_info.append({'path': path, 'license': license,'conclusion':conclusion})

        return not_allowed_licenses_info