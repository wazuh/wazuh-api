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
from wazuh.decoder import Decoder
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
    elif isinstance(o, Decoder):
        return o.to_dict()

    print_json("Wazuh-Python Internal Error: data encoding unknown", 1000)
    exit(1)

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
        '/agents/:agent_id': Agent.get_agent,
        '/agents/:agent_id/key': Agent.get_agent_key,
        '/agents': Agent.get_agents_overview,
        '/agents/total': Agent.get_total_agents,
        'PUT/agents/:agent_id/restart': Agent.restart_agents,
        'PUT/agents/:agent_name': Agent.add_agent,
        'POST/agents': Agent.add_agent,
        'DELETE/agents/:agent_id': Agent.remove_agent,

        '/decoders': Decoder.get_decoders,
        '/decoders?file': Decoder.get_decoders_by_file,
        '/decoders/parents': Decoder.get_parent_decoders,
        '/decoders/files': Decoder.get_decoders_files,
        '/decoders/:decoder_name': Decoder.get_decoders_by_name,

        '/manager/info': wazuh.get_ossec_init,
        '/manager/status': Manager.status,
        '/manager/configuration': Configuration.get_ossec_conf,
        '/manager/configuration/test': Configuration.check,
        '/manager/stats': Stats.totals,
        '/manager/stats/hourly': Stats.hourly,
        '/manager/stats/weekly': Stats.weekly,
        'PUT/manager/start': Manager.start,
        'PUT/manager/stop': Manager.stop,
        'PUT/manager/restart': Manager.restart,

        '/rootcheck/:agent_id': Rootcheck.print_db,
        '/rootcheck/:agent_id/last_scan': Rootcheck.last_scan,
        'PUT/rootcheck': Rootcheck.run,
        'DELETE/rootcheck': Rootcheck.clear,

        '/rules': Rule.get_rules,
        '/rules?group': Rule.get_rules_by_group,
        '/rules?file': Rule.get_rules_by_file,
        '/rules?level': Rule.get_rules_by_level,
        '/rules/groups': Rule.get_groups,
        '/rules/files': Rule.get_rules_files,
        '/rules/:rule_id': Rule.get_rules_by_id,

        '/syscheck/:agent_id/last_scan': Syscheck.last_scan,
        '/syscheck/:agent_id/files/changed': Syscheck.files_changed,
        '/syscheck/:agent_id/files/changed/total': Syscheck.files_changed_total,
        '/syscheck/:agent_id/registry/changed': Syscheck.registry_changed,
        '/syscheck/:agent_id/registry/changed/total': Syscheck.registry_changed_total,
        'PUT/syscheck': Syscheck.run,
        'DELETE/syscheck': Syscheck.clear

        }

    if list_f:
        print_json(sorted(functions.keys()))
        exit(0)

    # Check arguments
    pattern = re.compile(r'^[a-zA-Z0-9\.:_/?]+$')
    m = pattern.match(function_id)
    if not m:
        print_json("Wazuh-Python Internal Error: Bad argument: Function", 1000)
        exit(1)

    pattern = re.compile(r'^[a-zA-Z0-9\-/_\.\:\\\s,=\[\]"]+$')
    if arguments:
        m = pattern.match(arguments)
        if not m:
            print_json("Wazuh-Python Internal Error: Bad argument: Args", 1000)
            exit(1)

    pattern = re.compile(r'^\d+,\d+$')
    if pagination:
        m = pattern.match(pagination)
        if not m:
            print_json("Wazuh-Python Internal Error: Bad argument: Pagination", 1000)
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
