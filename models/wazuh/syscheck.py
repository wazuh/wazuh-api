#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agents import Agent

__all__ = ["Syscheck"]

class Syscheck:

    def __init__(self, path='/var/ossec'):
        self.path = path
        self.SYSCHECK_CONTROL = '{0}/bin/syscheck_control'.format(path)
        self.AGENT_CONTROL = '{0}/bin/agent_control'.format(path)

    def run(self, agent_id):
        if agent_id == "ALL":
            return execute([self.AGENT_CONTROL, '-j', '-r', '-a'])
        else:
            return execute([self.AGENT_CONTROL, '-j', '-r', '-u', agent_id])

    def clear(self, agent_id):
        if agent_id == "ALL":
            return execute([self.SYSCHECK_CONTROL, '-j', '-u', 'all'])
        else:
            return execute([self.SYSCHECK_CONTROL, '-j', '-u', agent_id])

    def last_scan(self, agent_id):
        agent = Agent(agent_id)
        agent.get()
        data = {'syscheckTime': agent.syscheckTime, 'syscheckEndTime': agent.syscheckEndTime};

        return data

    def files_changed(self, agent_id, filename=None):
        cmd = [self.SYSCHECK_CONTROL, '-j', '-i', agent_id]
        if filename:
            cmd.extend(['-f', filename])
        return execute(cmd)

    def files_changed_total(self, agent_id, filename=None):
        files = self.files_changed(agent_id, filename)
        return len(files)

    def registry_changed(self, agent_id, filename=None):
        cmd = [self.SYSCHECK_CONTROL, '-j', '-r', '-i', agent_id]
        if filename:
            cmd.extend(['-f', filename])
        return execute(cmd)

    def registry_changed_total(self, agent_id, filename=None):
        files = self.registry_changed(agent_id, filename)
        return len(files)
