#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import Wazuh
from wazuh.rules import Rule
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

    print_json("Wazuh-Python Internal Error", 1000)

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

def test():
    # Wazuh
    myWazuh = Wazuh()
    myWazuh.get_ossec_init()

    # Configuration
    myWazuh.configuration.get_ossec_conf()
    myWazuh.configuration.check()

    # Rules
    myWazuh.rules.get_rules()
    myWazuh.rules.get_rules(enabled=False)
    myWazuh.rules.get_rules_files(enabled=False)
    myWazuh.rules.get_rules_with_group(group="web", enabled=False)
    myWazuh.rules.get_rule(1002)
    myWazuh.rules.get_groups()

    # Stats
    myWazuh.stats.totals("2016","06","06")
    myWazuh.stats.hourly()
    myWazuh.stats.weekly()

    print("OK")
    exit(0)

if __name__ == "__main__":
    function = None
    arguments = None
    pretty = False
    debug = False
    # test()

    # Read arguments
    try:
        opts, args = getopt(argv[1:], "f:a:pdh", ["function=", "arguments", "pretty", "debug", "help"])
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
            function = a
        elif o in ("-a", "--arguments"):
            arguments = a
        elif o in ("-p", "--pretty"):
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
    m = pattern.match(function)
    if not m:
        print("bad argument function")
        exit(1)

    pattern = re.compile(r'[a-zA-Z0-9\-/_\.\:\\\s,="]+$')
    if arguments:
        m = pattern.match(arguments)
        if not m:
            print("bad argument arguments")
            exit(1)
    else:
        arguments = ""

    # Execution
    myWazuh = Wazuh()
    action = "myWazuh.{0}({1})".format(function, arguments)

    if debug:
        print(action)
    try:
        data = eval(action)
        print_json(data)
    except Exception as e:
        handle_exception(e)
