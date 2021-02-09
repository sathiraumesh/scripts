import requests
import uuid
import datetime
import time

from util import get_date_tommorow
class Server:

    def __init__(self,server_config):

        self.__host = server_config['host']
        self.__port = server_config['port']
        self.__username = server_config['username']
        self.__password = server_config['password']
        self.__entry = server_config['entry']
        self.__base_url = f'{self.__host}:{self.__port}{self.__entry}'
        self.__access_token = None
        self.__server_ping = 10


    def generate_access_token(self):
        auth_endpoint = f'{self.__base_url}/tokens'
        token_name = uuid.uuid4()
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'username': self.__username,
            'password': self.__password,
            'token_name': token_name,
            'token_scope': 'write',
            'token_expire': get_date_tommorow()
        }

        print("generating access token")
        response = requests.post(url=auth_endpoint, headers=headers, data=data);
        token = response.json()['Authorization']
        self.__access_token = token
        print("access token generation successful")
        return token;




    def upload_asset(self, access_token, asset_path):
        upload_endpoint = f'{self.__base_url}/uploads'
        files = {'fileInput': open(asset_path, 'br')}
        headers = {
            'folderId': '1',
            'uploadDescription': f'license scan {datetime.date.today()}',
            'public': 'public',
            'Authorization': access_token,

        }
        print("uploading asset started")
        response = requests.post(url=upload_endpoint, headers=headers, files=files)
        print("uploading asset successful")
        upload_id = response.json()['message']
        print(f'upload id :{upload_id}')
        return upload_id


    def __schedule_scan_request(self, access_token, upload_id):
        schedule_agent_endpoint = f'{self.__base_url}/jobs'
        headers = {
            'Content-Type': 'application/json',
            'folderId': '1',
            'uploadId': str(upload_id),
            'Authorization': access_token,

        }
        data = {
            'analysis': {
                'bucket': True,
                'copyright_email_author': True,
                'ecc': True,
                'keyword': True,
                'mime': True,
                'monk': True,
                'nomos': True,
                'package': True,
                'ojo': True

            },
            'decider': {
                'nomos_monk': True,
                'bulk_reused': True,
                'new_scanner': True
            },
            'reuse': {
                'reuse_upload': 0,
                'reuse_group': 0,
                'reuse_main': True,
                'reuse_enhanced': True
            }
        }


        response = requests.post(url=schedule_agent_endpoint, headers=headers, json=data)
        return response.json()

    def schedule_scanners(self, access_token, upload_id):
        print("scheduling scanners started")
        type =''
        while type != 'INFO':
            result =self.__schedule_scan_request(access_token,upload_id)
            type = result['type']
            print('waiting for the server to schedule scanners')
            time.sleep(self.__server_ping)
        print("scheduling scanners successful")



    def __check_license_scanning_status(self, access_token, upload_id):
        url = f'{self.__base_url}/jobs'
        params = {
            'upload': str(upload_id),
        }
        headers = {
            'Authorization': access_token,
        }

        response = requests.get(url=url, headers=headers, params=params)
        return response.json()[0]['status']

    def get_license_findings(self, access_token, upload_id):
        url = f'{self.__base_url}/uploads/{upload_id}/licenses'
        params = {
            'agent': 'nomos,monk,ojo',
            'container': 'true'
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': access_token,

        }

        status = 'processing'
        print("license scan started")
        while (status.lower() == 'processing'  ) :
            status = self.__check_license_scanning_status(access_token,upload_id)
            print("license scan in progress")
            time.sleep(self.__server_ping)
        print("getting results started")
        response = requests.get(url=url, headers=headers, params=params)
        print("getting results completed")
        return response.json()

    def get_access_token(self):
        return self.__access_token

