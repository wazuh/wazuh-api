#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import Wazuh
from wazuh.rules import Rule
from wazuh.agents import Agent
from wazuh.utils import cut_array
from sys import argv, exit
from getopt import getopt, GetoptError
import re
import json

def print_json(data, error=0):
    output = {'error': error}

    if error == 0:
        key = 'data'
    else:
        key = 'message'

    output[key] = data

    if pretty:
        print(json.dumps(output, default=encode_json, indent=4))
    else:
        print(json.dumps(output, default=encode_json))


def encode_json(o):
    if isinstance(o, Rule):
        return o.to_dict()
    elif isinstance(o, Agent):
        return o.to_dict()

    print_json("Wazuh-Python Internal Error: data encoding unknown", 1000)

def handle_exception(exception):
    if exception.__class__.__name__ == "WazuhException":
        print_json(exception.message, exception.code)
    else:
        print_json("Wazuh-Python Internal Error: {0}".format(str(exception)), 1000)
        if debug:
            raise exception

def usage():
    help_msg = '''
    Wazuh Control

    \tf, --function     Function to execute
    \ta, --arguments    Arguments of function
    \tp, --pretty       Pretty JSON
    \td, --debug        Debug mode
    \th, --help         Help
    '''
    print(help_msg)
    exit(1)

if __name__ == "__main__":
    function_id = None
    arguments = None
    pagination = None
    pretty = False
    debug = False

    # Read arguments
    try:
        opts, args = getopt(argv[1:], "f:a:p:Pdh", ["function=", "arguments", "pagination", "pretty", "debug", "help"])
        n_args = len(opts)
        if not (1 <= n_args <= 4):
            print("Incorrect number of arguments.\nTry '--help' for more information.")
            exit(1)
    except GetoptError as err_args:
        print(str(err_args))
        print("Try '--help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-f", "--function"):
            function_id = a
        elif o in ("-a", "--arguments"):
            arguments = a
        elif o in ("-p", "--pagination"):
            pagination = a
        elif o in ("-P", "--pretty"):
            pretty = True
        elif o in ("-d", "--debug"):
            debug = True
        elif o in ("-h", "--help"):
            usage()
        else:
            usage()
            exit(1)

    # Check arguments
    pattern = re.compile(r'^[a-zA-Z0-9\._]+$')
    m = pattern.match(function_id)
    if not m:
        print_json("Wazuh-Python Internal Error: Bad argument", 1000)
        exit(1)

    pattern = re.compile(r'^[a-zA-Z0-9\-/_\.\:\\\s,=\[\]"]+$')
    if arguments:
        m = pattern.match(arguments)
        if not m:
            print_json("Wazuh-Python Internal Error: Bad argument", 1000)
            exit(1)

    pattern = re.compile(r'^\d+,\d+$')
    if pagination:
        m = pattern.match(pagination)
        if not m:
            print_json("Wazuh-Python Internal Error: Bad argument", 1000)
            exit(1)

    wazuh = Wazuh()
    functions = {
        'wazuh.get_ossec_init': wazuh.get_ossec_init,
        'configuration.get_ossec_conf': wazuh.configuration.get_ossec_conf,
        'configuration.check': wazuh.configuration.check,
        'rules.get_rules': wazuh.rules.get_rules,
        'rules.get_rules_files': wazuh.rules.get_rules_files,
        'rules.get_rules_with_group': wazuh.rules.get_rules_with_group,
        'rules.get_rules_with_file': wazuh.rules.get_rules_with_file,
        'rules.get_rules_with_level': wazuh.rules.get_rules_with_level,
        'rules.get_rule': wazuh.rules.get_rule,
        'rules.get_groups': wazuh.rules.get_groups,
        'manager.stats.totals': wazuh.manager.stats.totals,
        'manager.stats.hourly': wazuh.manager.stats.hourly,
        'manager.stats.weekly': wazuh.manager.stats.weekly,
        'manager.status': wazuh.manager.status,
        'manager.start': wazuh.manager.start,
        'manager.stop': wazuh.manager.stop,
        'manager.restart': wazuh.manager.restart,
        'rootcheck.run': wazuh.rootcheck.run,
        'rootcheck.clear': wazuh.rootcheck.clear,
        'rootcheck.print_db': wazuh.rootcheck.print_db,
        'rootcheck.last_scan': wazuh.rootcheck.last_scan,
        'syscheck.run': wazuh.syscheck.run,
        'syscheck.clear': wazuh.syscheck.clear,
        'syscheck.last_scan': wazuh.syscheck.last_scan,
        'syscheck.files_changed': wazuh.syscheck.files_changed,
        'syscheck.files_changed_total': wazuh.syscheck.files_changed_total,
        'syscheck.registry_changed': wazuh.syscheck.registry_changed,
        'syscheck.registry_changed_total': wazuh.syscheck.registry_changed_total,
        'agents.get_agent': wazuh.agents.get_agent,
        'agents.get_agent_key': wazuh.agents.get_agent_key,
        'agents.restart': wazuh.agents.restart,
        'agents.remove_agent': wazuh.agents.remove_agent,
        'agents.add_agent': wazuh.agents.add_agent,
        'agents.get_agents_overview': wazuh.agents.get_agents_overview,
        'agents.get_total': wazuh.agents.get_total
        }

    try:
        if arguments:
            data = functions[function_id](*arguments.split(','))
        else:
            data = functions[function_id]()

        if pagination and type(data) is list:
            offset_limit = pagination.split(',')
            data = cut_array(data, offset_limit[0], offset_limit[1])

        print_json(data)
    except Exception as e:
        handle_exception(e)
