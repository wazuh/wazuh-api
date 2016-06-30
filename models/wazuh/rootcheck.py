#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, cut_array, sort_array
from wazuh.agent import Agent
from wazuh import common

def run(agent_id=None, all_agents=False):
    if all_agents:
        return execute([common.agent_control, '-j', '-r', '-a'])
    else:
        return execute([common.agent_control, '-j', '-r', '-u', agent_id])

def clear(agent_id=None, all_agents=False):
    if all_agents:
        return execute([common.rootcheck_control, '-j', '-u', 'all'])
    else:
        return execute([common.rootcheck_control, '-j', '-u', agent_id])

def print_db(agent_id, offset=0, limit=0, sort=None):
    data = execute([common.rootcheck_control, '-j', '-i', agent_id])
    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['oldDay'], 'asc')
    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'rootcheckTime': agent.rootcheckTime, 'rootcheckEndTime': agent.rootcheckEndTime};

    return data
