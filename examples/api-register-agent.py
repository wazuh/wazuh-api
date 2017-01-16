#!/usr/bin/env python

###
#  Python script for registering agents automatically with the API
#  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

import os
import json
import sys
from subprocess import PIPE, Popen
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


def add_agent(agt_name, agt_ip=None):
    if agt_ip:
        status_code, response = req('post', '/agents', {'name': agt_name, 'ip': agt_ip})
    else:
        status_code, response = req('post', '/agents', {'name': agt_name})

    if status_code == 200 and response['error'] == 0:
        r_id = response['data']
        return r_id
    else:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = "Status: {0} - {1}".format(status_code, code_desc(status_code))
        exit("ERROR - ADD AGENT:\n{0}\n{1}".format(code, msg))


def get_key(agent_id):
    status_code, response = req('get', '/agents/{0}/key'.format(agent_id))
    if status_code == 200 and response['error'] == 0:
        r_key = response['data']
        return r_key
    else:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = "Status: {0} - {1}".format(status_code, code_desc(status_code))
        exit("ERROR - GET KEY AGENT:\n{0}\n{1}".format(code, msg))


def import_key(agent_key):
    cmd = "/var/ossec/bin/manage_agents"
    std_out, std_err, r_code = execute([cmd, "-i", agent_key], "y\n\n")
    if r_code != 0:
        exit("ERROR - IMPORT KEY:{0}".format(std_err))

def get_hostname():
    out, err, r_code = execute(["hostname"])
    if r_code != 0:
        exit("ERROR: Hostname unknown: {0}".format(e))

    hostname = out.strip()

    return hostname

def execute(cmd_list, stdin=None):
    p = Popen(cmd_list, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    std_out, std_err = p.communicate(stdin)
    return_code = p.returncode
    return std_out, std_err, return_code

def restart_ossec():
    cmd = "/var/ossec/bin/ossec-control"
    std_out, std_err, r_code = execute([cmd, "restart"])
    restarted = False

    for line_output in std_out.split(os.linesep):
        if "Completed." in line_output:
            restarted = True
            break

    if not restarted:
        exit("ERROR - RESTARTING OSSEC:{0}".format(std_err))

if __name__ == "__main__":
    # Configuration
    base_url = 'http://10.0.0.1:55000'
    auth = HTTPBasicAuth('foo', 'bar')
    agent_name = "auto"
    verify = False  # Use with self-signed certificates.

    print("Adding agent.")
    if agent_name == "auto":
        agent_name = get_hostname()

    agent_id = add_agent(agent_name)
    print("Agent '{0}' with ID '{1}' added.".format(agent_name, agent_id))

    print("Getting agent key.")
    agent_key = get_key(agent_id)

    print("Importing authentication key.")

    import_key(agent_key)

    print("Restarting.")

    restart_ossec()
