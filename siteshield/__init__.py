#!/usr/bin/env python
# Akamai site shield module
# Reference https://developer.akamai.com/api/luna/siteshield/overview.html

import requests
import json
from akamai.edgegrid import EdgeGridAuth
from urlparse import urljoin


class Client(object):

    def __init__(self, base_url, client_token, client_secret, access_token):
        self.base_url = base_url
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token
        self.session = requests.Session()
        self.headers = {'Content-Type': 'application/json'}
        self.session.auth = EdgeGridAuth(
            client_token=self.client_token,
            client_secret=self.client_secret,
            access_token=self.access_token,
            max_body=128 * 1024
        )

    def list_maps(self):
        return json.dumps(self.session.get(urljoin(self.base_url, '/siteshield/v1/maps')).json(),
                          indent=2)

    def get_map(self, map_id):
        self.map_id = map_id
        return json.dumps(self.session.get(urljoin(self.base_url, '/siteshield/v1/maps/' + self.map_id)).json(),
                          indent=2)

    def ack_map(self, map_id):
        self.map_id = map_id
        return json.dumps(
            self.session.post(urljoin(self.base_url, '/siteshield/v1/maps/' + self.map_id + '/acknowledge')).json(),
            indent=2)
