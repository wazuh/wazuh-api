#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agent import Agent
from wazuh import common

def run(agent_id):
    if agent_id == "ALL":
        return execute([common.agent_control, '-j', '-r', '-a'])
    else:
        return execute([common.agent_control, '-j', '-r', '-u', agent_id])

def clear(agent_id):
    if agent_id == "ALL":
        return execute([common.syscheck_control, '-j', '-u', 'all'])
    else:
        return execute([common.syscheck_control, '-j', '-u', agent_id])

def last_scan(agent_id):
    agent = Agent(agent_id)
    agent.get()
    data = {'syscheckTime': agent.syscheckTime, 'syscheckEndTime': agent.syscheckEndTime};

    return data

def files_changed(agent_id, filename=None, filetype='file'):
    cmd = [common.syscheck_control, '-j', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    return execute(cmd)

def files_changed_total(agent_id, filename=None):
    files = Syscheck.files_changed(agent_id, filename)
    return len(files)

def registry_changed(agent_id, filename=None):
    cmd = [common.syscheck_control, '-j', '-r', '-i', agent_id]
    if filename:
        cmd.extend(['-f', filename])
    return execute(cmd)

def registry_changed_total(agent_id, filename=None):
    files = Syscheck.registry_changed(agent_id, filename)
    return len(files)
