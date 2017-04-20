#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sys import exit, path, argv
from os import getcwd
from getopt import GetoptError, getopt
from signal import signal, SIGINT

# Set framework path
try:
    cwd = getcwd()
    last_dir = cwd.split('/')[-1]

    if last_dir == 'bin':
        framework_path = '{0}/api/framework'.format(cwd[:-4])
    elif last_dir == 'scripts':
        framework_path = cwd[:-8]
    else:
        exit("Error: Framework path not found.")

    path.append(framework_path)
except Exception as e:
    exit("Error: Framework path not found: {0}".format(e))

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.agent import Agent
    from wazuh.exception import WazuhException
    from wazuh.configuration import get_group_files
except Exception as e:
    exit("No module 'wazuh' found: {0}".format(e))

# Global variables
debug = False

# Functions
def get_stdin(msg):
    try:
        stdin = raw_input(msg)
    except:
        # Python 3
        stdin = input(msg)
    return stdin


def signal_handler(n_signal, frame):
    print("")
    exit(1)


def show_groups():
    groups_data = Agent.get_all_groups(limit=None)

    print("Groups ({0}):".format(groups_data['totalItems']))
    for g in groups_data['items']:
        print("  {0}".format(g))


def show_group(agent_id):
    agent_info = Agent(id=agent_id).get_basic_information()

    str_group = agent_info['group'] if 'group' in agent_info else "Null"
    print("The agent '{0}' with ID '{1}' has the group: '{2}'.".format(agent_info['name'], agent_info['id'], str_group))


def show_agents_with_group(group_id):
    agents_data = Agent.get_agent_group(group_id, limit=0)

    if agents_data['totalItems'] == 0:
        print("Any agent with group '{0}'.".format(group_id))
    else:
        print("{0} agent(s) in group '{1}':".format(agents_data['totalItems'], group_id))
        for agent in agents_data['items']:
            print("  ID: {0}  Name: {1}.".format(agent['id'], agent['name']))


def show_group_files(group_id):
    print("Files for group '{0}':".format(group_id))
    for f in get_group_files(group_id):
        print("  {0}".format(f))


def remove_group(agent_id, force=False):
    ans = 'n'
    if not force:
         ans = get_stdin("Do you want to remove the current group of agent '{0}'? [y/N]: ".format(agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = Agent.remove_group(agent_id)
    else:
        msg = "Cancelled."

    print(msg)


def remove_group_all_agents(group_id, force=False):
    ans = 'n'
    if not force:
         ans = get_stdin("Do you want to remove the '{0}' group of every agent? [y/N]: ".format(group_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        data = Agent.remove_group_in_every_agent(group_id)
        msg = data['msg']
        msg += "\nAffected agents: {0}.".format(', '.join(data['affected_agents']))
    else:
        msg = "Cancelled."

    print(msg)


def set_group(agent_id, group_id, force=False):
    ans = 'n'
    if not force:
         ans = get_stdin("Do you want to set the group '{0}' to the agent '{1}'? [y/N]: ".format(group_id, agent_id))
    else:
        ans = 'y'

    if ans.lower() == 'y':
        msg = Agent.set_group(agent_id, group_id)
    else:
        msg = "Cancelled."

    print(msg)


def usage():
    msg = """
    agent_groups.py [  -i agent_id [ -r [-f] ] |  -g group_id  [ -a | -l | -s agent_id [-f] | -r [-f] ]  ]

    Usage:
    ./agent_groups.py                                   # List all groups
    ./agent_groups.py -g group_id -a                    # List agents in group
    ./agent_groups.py -g group_id -l                    # List files in group
    ./agent_groups.py -g group_id -s agent_id [-f]      # Set group to agent
    ./agent_groups.py -g group_id -r [-f]               # Remove the group in every agent
    ./agent_groups.py -i agent_id                       # Get group of agent
    ./agent_groups.py -i agent_id -r [-f]               # Remove the current group of the agent

    Params:
    \t-i, --agent-id
    \t-g, --group
    \t-a, --list-agents
    \t-l, --list-files
    \t-s, --set-group
    \t-r, --remove-group
    \t-f, --force
    \t-d, --debug
    """
    print(msg)


def main():
    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    # Initialize framework
    myWazuh = Wazuh(get_init=True)

    # Arguments
    arguments = {'n_args': 0, 'group_id': None, 'agent_id': None, 'force': False, 'list_agents': False, 'list_files': False, 'set_group': False, 'remove_group': False,  }
    try:
        opts, args = getopt(argv[1:], "i:g:als:rfhd", ["agent-id=", "group=", "list-agents", "list-files", "set-group=", "remove-group", "force", "help", "debug"])
        arguments['n_args'] = len(opts)
        if arguments['n_args'] > 4:
            print("Incorrect number of arguments.\nTry './agent_groups.py --help' for more information.")
            exit(1)
    except GetoptError as err:
        print(str(err) + "\n" + "Try './agent_groups.py --help' for more information.")
        exit(1)

    for o, a in opts:
        if o in ("-i", "--agent-id"):
            arguments['agent_id'] = a
        elif o in ("-g", "group"):
            arguments['group_id'] = a
        elif o in ("-a", "list-agents"):
            arguments['list_agents'] = True
        elif o in ("-l", "list-files"):
            arguments['list_files'] = True
        elif o in ("-s", "set-group"):
            arguments['set_group'] = True
            arguments['agent_id'] = a
        elif o in ("-r", "remove-group"):
            arguments['remove_group'] = True
        elif o in ("-f", "force"):
            arguments['force'] = True
        elif o in ("-d", "--debug"):
            global debug
            debug = True
        elif o in ("-h", "--help"):
            usage()
            exit(0)
        else:
            usage()
            exit(1)

    # No arguments
    if arguments['n_args'] == 0:
        show_groups()
    # -i agent_id [ -r [-f] ]
    elif arguments['agent_id'] and not arguments['group_id']:
        if arguments['remove_group']:
            remove_group(arguments['agent_id'], arguments['force'])
        else:
            show_group(arguments['agent_id'])
    #  -g group_id  [ -a | -l | -s agent_id [-f] | -r [-f] ]  ]
    elif arguments['group_id']:
        # -g group_id -a
        if arguments['list_agents']:
            show_agents_with_group(arguments['group_id'])
        # -g group_id -l
        elif arguments['list_files']:
            show_group_files(arguments['group_id'])
        # -g group_id -s agent_id [-f]
        elif arguments['set_group']:
            set_group(arguments['agent_id'], arguments['group_id'], arguments['force'])
        # -g group_id -r [-f]
        elif arguments['remove_group']:
            remove_group_all_agents(arguments['group_id'], arguments['force'])

if __name__ == "__main__":

    try:
        main()
    except WazuhException as e:
        print("Error {0}: {1}".format(e.code, e.message))
        if debug:
            raise
    except Exception as e:
        print("Internal error: {0}".format(str(e)))
        if debug:
            raise
