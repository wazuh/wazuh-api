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
        return execute([common.syscheck_control, '-j', '-u', 'all'])
    else:
        return execute([common.syscheck_control, '-j', '-u', agent_id])

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'syscheckTime': agent.syscheckTime, 'syscheckEndTime': agent.syscheckEndTime};

    return data

def files_changed(agent_id, filename=None, filetype='file', offset=0, limit=0, sort=None):
    cmd = [common.syscheck_control, '-j', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    data = execute(cmd)

    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['date', 'file'], 'asc')

    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

def files_changed_total(agent_id, filename=None):
    return files_changed(agent_id, filename)['totalItems']

def registry_changed(agent_id, filename=None, offset=0, limit=0, sort=None):
    cmd = [common.syscheck_control, '-j', '-r', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    data = execute(cmd)

    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['date', 'file'], 'asc')

    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

def registry_changed_total(agent_id, filename=None):
    return registry_changed(agent_id, filename)['totalItems']
