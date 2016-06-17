#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agents import Agent

__all__ = ["Rootcheck"]

class Rootcheck:

    def __init__(self, path='/var/ossec'):
        self.path = path
        self.ROOTCHECK_CONTROL = '{0}/bin/rootcheck_control'.format(path)
        self.AGENT_CONTROL = '{0}/bin/agent_control'.format(path)

    def run(self, agent_id):
        if agent_id == "ALL":
            return execute([self.AGENT_CONTROL, '-j', '-r', '-a'])
        else:
            return execute([self.AGENT_CONTROL, '-j', '-r', '-u', agent_id])

    def clear(self, agent_id):
        if agent_id == "ALL":
            return execute([self.ROOTCHECK_CONTROL, '-j', '-u', 'all'])
        else:
            return execute([self.ROOTCHECK_CONTROL, '-j', '-u', agent_id])

    def print_db(self, agent_id):
        return execute([self.ROOTCHECK_CONTROL, '-j', '-i', agent_id])

    def last_scan(self, agent_id):
        agent = Agent(agent_id)
        agent.get()
        data = {'rootcheckTime': agent.rootcheckTime, 'rootcheckEndTime': agent.rootcheckEndTime};

        return data
