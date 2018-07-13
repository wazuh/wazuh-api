#!/usr/bin/env python
###
#  API RESTful for OSSEC
#  Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

# How to use OSSEC Wazuh RESTful API from Python
# Requests module: http://docs.python-requests.org/
# Documentation: https://documentation.wazuh.com/current/user-manual/api/index.html

import json
import sys
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit()


def req(method, resource, data=None):
    url = '{0}/{1}'.format(base_url, resource)

    try:
        requests.packages.urllib3.disable_warnings()

        if method.lower() == 'post':
            r = requests.post(url, auth=auth, data=data, verify=verify)
        elif method.lower() == 'put':
            r = requests.put(url, auth=auth, data=data, verify=verify)
        elif method.lower() == 'delete':
            r = requests.delete(url, auth=auth, data=data, verify=verify)
        else:
            r = requests.get(url, auth=auth, params=data, verify=verify)

        code = r.status_code
        res_json = r.json()

    except Exception as exception:
        print("Error: {0}".format(exception))
        sys.exit(1)

    return code, res_json


def code_desc(http_status_code):
    return requests.status_codes._codes[http_status_code][0]

if __name__ == "__main__":
    # Configuration
    base_url = 'https://localhost:55000'
    auth = HTTPBasicAuth('foo', 'bar')
    verify = False  # Use with self-signed certificates.

    print("Welcome:")
    status_code, response = req('get', '/')
    print(json.dumps(response, indent=4, sort_keys=True))
    print("Status: {0} - {1}".format(status_code, code_desc(status_code)))

    print("\nAgents:")
    status_code, response = req('get', '/agents')
    print(json.dumps(response, indent=4, sort_keys=True))
    print("Status: {0} - {1}".format(status_code, code_desc(status_code)))

    print("\nManager:")
    status_code, response = req('get', '/manager/status')
    print(json.dumps(response, indent=4, sort_keys=True))
    print("Status: {0} - {1}".format(status_code, code_desc(status_code)))

    print("\n\nWazuh.com")
