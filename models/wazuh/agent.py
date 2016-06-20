#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh import common

class Agent:
    def __init__(self, id=-1):
        self.id = id

        self.status = None
        self.name = None
        self.ip = None
        self.lastKeepAlive = None
        self.version = None
        self.os = None
        self.rootcheckTime = None
        self.rootcheckEndTime = None
        self.syscheckTime = None
        self.syscheckEndTime = None

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'status': self.status, 'name': self.name, 'ip': self.ip, 'id': self.id, 'lastKeepAlive': self.lastKeepAlive, 'version': self.version, 'os': self.os, 'rootcheckTime': self.rootcheckTime, 'rootcheckEndTime': self.rootcheckEndTime, 'syscheckTime': self.syscheckTime, 'syscheckEndTime': self.syscheckEndTime}
        return dictionary

    def get(self):
        data_agent = execute([common.agent_control, '-j', '-e', '-i', self.id])

        self.status = data_agent['status']
        self.name = data_agent['name']
        self.ip = data_agent['ip']
        self.id = data_agent['id']
        self.lastKeepAlive = data_agent['lastKeepAlive']
        self.version = data_agent['version']
        self.os = data_agent['os']
        self.rootcheckTime = data_agent['rootcheckTime']
        self.rootcheckEndTime = data_agent['rootcheckEndTime']
        self.syscheckTime = data_agent['syscheckTime']
        self.syscheckEndTime = data_agent['syscheckEndTime']

    def get_key(self):
        self.key = execute([common.manage_agents, '-j', '-e', self.id])
        return self.key

    def restart(self):
        return execute([common.agent_control, '-j', '-R', '-u', self.id])

    def remove(self):
        return execute([common.manage_agents, '-j', '-r', self.id])

    def add(self, name, ip):
        if ip.lower() == 'any':
            cmd = [common.manage_agents, '-j', '-a', 'any', '-n', name]
        else:
            cmd = [common.manage_agents, '-j', '-a', ip, '-n', name];

        self.id = execute(cmd)['id']
        return self.id

    @staticmethod
    def get_agents_overview(status="all"):
        agents = execute([common.agent_control, '-j', '-l'])
        if status.lower() == "all":
            return agents
        else:
            new_agents = []
            for agent in agents:
                if agent['status'].lower() == status.lower():
                    new_agents.append(agent)
            return new_agents

    @staticmethod
    def get_total_agents(status="all"):
        return len(Agent.get_agents_overview(status))

    @staticmethod
    def restart_agents(agent_id):
        if agent_id == "ALL":
            return execute([common.agent_control, '-j', '-R', '-a'])
        else:
            agent = Agent(agent_id)
            return agent.restart()

    @staticmethod
    def get_agent(agent_id):
        agent = Agent(agent_id)
        agent.get()
        return agent

    @staticmethod
    def get_agent_key(agent_id):
        agent = Agent(agent_id)
        return agent.get_key()

    @staticmethod
    def remove_agent(agent_id):
        agent = Agent(agent_id)
        return agent.remove()

    @staticmethod
    def add_agent(name, ip):
        agent = Agent()
        return agent.add(name, ip)
