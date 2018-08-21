###!/usr/bin/env python

###
#  Python script for registering agents automatically with the API
#  Copyright (C) 2018 Wazuh, Inc. All rights reserved.
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
import argparse, getpass
import urlparse
from subprocess import PIPE, Popen
try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit()

OSSEC_CONF_PATH = '/var/ossec/etc/ossec.conf'
verify = false

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


def add_agent(agt_name, agt_ip=None, force=False):
    data = {}
    data['name'] = agt_name
    if agt_ip: 
        data['ip'] = agt_ip
    if force:
       data['force'] = 0
    status_code, response = req('post', 'agents', data)

    if status_code == 200 and response['error'] == 0:
        r_id  = response['data']['id']
        r_key = response['data']['key']
        return r_id, r_key
    else:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = "Status: {0} - {1}".format(status_code, code_desc(status_code))
        exit("ERROR - ADD AGENT:\n{0}\n{1}".format(code, msg))


def set_group(agent_id, group_id):
    status_code, response = req('put', "agents/{}/group/{}".format(agent_id, group_id))
    if status_code != 200 or response['error'] != 0:
        msg = json.dumps(response, indent=4, sort_keys=True)
        code = "Status: {0} - {1}".format(status_code, code_desc(status_code))
        exit("ERROR - SET AGENT GROUP:\n{0}\n{1}".format(code, msg))


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


def conf_exists():
    if os.path.isfile(OSSEC_CONF_PATH): return True
    return False


def update_manager_host(manager_host):
    #as the ossec.conf does not parse as valid xml, the method to replace the MANAGER_IP has to be slightly creative. 
    #Read all file. 
    with open(OSSEC_CONF_PATH, 'r') as file: 
        filedata = file.read()
    file.close()
    filedata = filedata.split("\n")

    #Write all file and replace the address portion. 
    f = open(OSSEC_CONF_PATH, 'w')
    for line in filedata: 
        if "<address>" in line.lower() and "</address>" in line.lower():
            #Copy until the end of the first address tag. This is to preserve tab format. 
            line = line[0:line.find(">")+1]+ "{}</address>".format(manager_host)
        f.write(line+"\n")
    f.close()  


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


def process(wazuh_url, agent_name, username, password, group=None, verify=False, force=False): 
    auth = HTTPBasicAuth(username, password)
    print("Adding agent.")

    agent_id, agent_key = add_agent(agt_name=agent_name,force=force)
    print("Agent '{0}' with ID '{1}' added.".format(agent_name, agent_id))

    if group is not None: 
        print ("Setting agent group to {}".format(group))
	    set_group(agent_id, group)
        print ("Agent group set")

    print("Importing authentication key.")
    import_key(agent_key)
    
    print("Changing ossec.conf manager IP settings")
    parsed_uri = urlparse.urlparse(base_url)
    manager_host =  parsed_uri.netloc.split(':')[0]
    update_manager_host(manager_host)

    print("Restarting.")
    restart_ossec()


def main(): 
    #main() only gets config params from the user via either cmd line args
    #or interactive mode and passes them on to the process() function.  
    interactive = True
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Run this script in interactive mode without providing any parameters: #python api-register-agent.py. You can also provide all configuration paramters via cmd parameters as follows. ")
    parser.add_argument('-w', '--wazuh-url', help='The Wazuh API url. Required.')
    parser.add_argument('-n', '--agent-name', help='The new agent name, typically the hostname. Required.')
    parser.add_argument('-u', '--username', help='The Wazuh API username. Required.')
    parser.add_argument('-p', '--password', help='The Wazuh API password. Required.')
    parser.add_argument('-g', '--group', help='The Wazuh agent group. If unspecified, the default group will be used.')
    parser.add_argument('-v', '--verify-cert', help='Certificate validation, keep False for self-signed certificates (if not using https, just ignore). Default False.', action ='store_true')
    parser.add_argument('-f', '--force', help='Force replacement of agent. Useful when if agent IP is already registered. Default False.', action='store_true') 
    args = parser.parse_args()

    #if user fills up at least one cmd line argument, he does not want the interactive mode.
    if (args.wazuh_url or args.agent_name or args.username or args.password):
        #the required params for the cmd mode are url, agent name, username, password.
        #if these not filled in show message and exit. 
        interactive = False
        if not (args.wazuh_url and args.agent_name and args.username and args.password):
            exit ('The wazuh-url, agent-name, username and password parameters are mandatory. E.g. At a minimum: \n\n# python api-register-agent.py -w https://wazuh-api.myserver.com:5000 -n MyWebserver -u wazuh -p demo666\n\n Otherwise do not specify any params and use the interactive mode\n Use -h flag for help.')

    if not conf_exists(): 
        exit("{} was not found. Do you have the wazuh-agent installed? See https://documentation.wazuh.com/current/installation-guide/installing-wazuh-agent/index.html".format(OSSEC_CONF_PATH)    
 
    if interactive: #ask user for all details
        agent_name = raw_input("Please enter an agent Name. Default:[{}]: ".format(get_hostname())) or get_hostname()
        group = raw_input("Enter the Wazuh Agent group you would like to put this Agent in. Default:[default]: ") or None
        base_url = raw_input("Enter the Wazuh API Url (E.g. https://200.10.10.10:55000, or https://wzh.myserver.com:55000): ")
        verify = False
        if base_url.lower().startswith("https"):
            verify = raw_input("Verify SSL certificate of API endpoint? (y/n) Default:[n]: ") or False
            if verify in ('y', 'Y', 'yes', 'Yes', 'YES'): verify = True
        if "55000" not in base_url: print ("*Warning*: Your URL does not seem to include the default port 55000. This is fine if your wazuh API is listening on a different port.")
        if "http" not in base_url: print ("*Warning*: Your URL does not include a protocol (http:// or https://)")
        username = raw_input ("Enter the Wazuh API username. Default:[wazuh]: ") or "wazuh"
        password = getpass.getpass("Enter the Wazuh API Password and press ENTER: ")
        force = False
        force = raw_input("Force REPLACING of Agent if IP already exists? (y/n) Default:[n] ") or "n"
        if force in ('y', 'Y', 'yes', 'Yes', 'YES'):
            force = True
    else: #get the details from the cmd args. 
	agent_name = args.agent_name
        group = args.group
        base_url = args.wazuh_url
        username = args.username
        password = args.password
        force = args.force
        verify = args.verify_cert


if __name__ == "__main__":
    main()
