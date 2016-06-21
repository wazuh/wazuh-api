#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from sys import argv, exit
from getopt import getopt, GetoptError
import re
import json

from wazuh import Wazuh
from wazuh.agent import Agent
from wazuh.configuration import Configuration
from wazuh.manager import Manager
from wazuh.stats import Stats
from wazuh.rootcheck import Rootcheck
from wazuh.syscheck import Syscheck
from wazuh.rule import Rule
from wazuh.utils import cut_array


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
    \tp, --pagination   Pagination
    \tP, --pretty       Pretty JSON
    \td, --debug        Debug mode
    \tl, --list         List functions
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
    list_f = False

    # Read arguments
    try:
        opts, args = getopt(argv[1:], "f:a:p:Pdlh", ["function=", "arguments", "pagination", "pretty", "debug", "list", "help"])
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
        elif o in ("-l", "--list"):
            list_f = True
        elif o in ("-h", "--help"):
            usage()
        else:
            usage()
            exit(1)


    wazuh = Wazuh()

    functions = {
        'wazuh.get_ossec_init': wazuh.get_ossec_init,
        'configuration.get_ossec_conf': Configuration.get_ossec_conf,
        'configuration.check': Configuration.check,
        'rules.get_rules': Rule.get_rules,
        'rules.get_rules_files': Rule.get_rules_files,
        'rules.get_rules_with_group': Rule.get_rules_with_group,
        'rules.get_rules_with_file': Rule.get_rules_with_file,
        'rules.get_rules_with_level': Rule.get_rules_with_level,
        'rules.get_rule': Rule.get_rule,
        'rules.get_groups': Rule.get_groups,
        'manager.stats.totals': Stats.totals,
        'manager.stats.hourly': Stats.hourly,
        'manager.stats.weekly': Stats.weekly,
        'manager.status': Manager.status,
        'manager.start': Manager.start,
        'manager.stop': Manager.stop,
        'manager.restart': Manager.restart,
        'rootcheck.run': Rootcheck.run,
        'rootcheck.clear': Rootcheck.clear,
        'rootcheck.print_db': Rootcheck.print_db,
        'rootcheck.last_scan': Rootcheck.last_scan,
        'syscheck.run': Syscheck.run,
        'syscheck.clear': Syscheck.clear,
        'syscheck.last_scan': Syscheck.last_scan,
        'syscheck.files_changed': Syscheck.files_changed,
        'syscheck.files_changed_total': Syscheck.files_changed_total,
        'syscheck.registry_changed': Syscheck.registry_changed,
        'syscheck.registry_changed_total': Syscheck.registry_changed_total,
        'agents.get_agent': Agent.get_agent,
        'agents.get_agent_key': Agent.get_agent_key,
        'agents.restart': Agent.restart_agents,
        'agents.remove_agent': Agent.remove_agent,
        'agents.add_agent': Agent.add_agent,
        'agents.get_agents_overview': Agent.get_agents_overview,
        'agents.get_total': Agent.get_total_agents
        }

    if list_f:
        print_json(functions.keys())
        exit(0)

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

    # Execute

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
