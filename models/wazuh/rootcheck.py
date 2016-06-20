#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agent import Agent
from wazuh import common

class Rootcheck:

    @staticmethod
    def run(agent_id):
        if agent_id == "ALL":
            return execute([common.agent_control, '-j', '-r', '-a'])
        else:
            return execute([common.agent_control, '-j', '-r', '-u', agent_id])

    @staticmethod
    def clear(agent_id):
        if agent_id == "ALL":
            return execute([common.rootcheck_control, '-j', '-u', 'all'])
        else:
            return execute([common.rootcheck_control, '-j', '-u', agent_id])

    @staticmethod
    def print_db(agent_id):
        return execute([common.rootcheck_control, '-j', '-i', agent_id])

    @staticmethod
    def last_scan(agent_id):
        agent = Agent(agent_id)
        agent.get()
        data = {'rootcheckTime': agent.rootcheckTime, 'rootcheckEndTime': agent.rootcheckEndTime};

        return data
