#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import getopt
import sys
import subprocess
import json


def usage():
    print("remove_agents.py -i agent_id [-p]")

if __name__ == "__main__":
    r_error = 0
    r_description = ""
    r_response = ""
    print_response = False
    mandatory_args = 0
    
    # Check arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:ph", ["id=", "print", "help"])
        if 1 > len(opts) > 2:
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            sys.exit()
    except getopt.GetoptError as err:
        print(str(err))
        print("Try '--help' for more information.")
        sys.exit()

    for o, a in opts:
        if o in ("-i", "--id"):
            agent_id = a
            mandatory_args += 1
        elif o in ("-p", "--print"):
            print_response = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            usage()
            sys.exit()

    if mandatory_args != 1:
            usage()
            sys.exit()

    # Check output
    output = ""
    err = ""
    try:
        p = subprocess.Popen(["/var/ossec/bin/manage_agents", "-r", agent_id], stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        
        if err:
            r_error = 51
            r_description = "Error unknown."
        elif "** Invalid ID" in output:
            r_error = 52
            r_description = "Invalid agent ID: '{0}'.".format(agent_id)
        elif "** No agent available." in output:
            r_error = 53
            r_description = "There are no agents."
        elif "** You must restart OSSEC for your changes to take effect" in output:
            r_error = 0
            r_response = "Agent {0} removed.".format(agent_id)
        else:
            r_error = 54
            r_description = "Error unknown."
    except:
        r_error = 50
        r_description = "Problem running command."

    # Response
    response = {'error': r_error}
    if r_error == 0:
        response['response'] = r_response
    else:
        response['description'] = r_description

    if print_response:
        for field in response:
            print("{0}: {1}".format(field, response[field]))
    else:
        print(json.dumps(response))
