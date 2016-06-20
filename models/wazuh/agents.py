#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute

__all__ = ["Agents", "Agent"]

MANAGE_AGENT = '/var/ossec/bin/manage_agents'
AGENT_CONTROL = '/var/ossec/bin/agent_control'

class Agents:

    def __init__(self, path='/var/ossec'):
        self.path = path
        global MANAGE_AGENT
        global AGENT_CONTROL
        MANAGE_AGENT = '{0}/bin/manage_agents'.format(path)
        AGENT_CONTROL = '{0}/bin/agent_control'.format(path)

    def restart(self, agent_id):
        if agent_id == "all":
            return execute([AGENT_CONTROL, '-j', '-R', '-a'])
        else:
            return Agent(agent_id).restart()

    def get_agents_overview(self, status="all"):
        agents = execute([AGENT_CONTROL, '-j', '-l'])
        if status.lower() == "all":
            return agents
        else:
            new_agents = []
            for agent in agents:
                if agent['status'].lower() == status.lower():
                    new_agents.append(agent)
            return new_agents

    def get_total(self, status="all"):
        return len(self.get_agents_overview(status))

    def get_agent(self, agent_id):
        agent = Agent(agent_id)
        agent.get()
        return agent

    def get_agent_key(self, agent_id):
        return Agent(agent_id).get_key()

    def remove_agent(self, agent_id):
        return Agent(agent_id).remove()

    def add_agent(self, name, ip):
        return Agent().add(name, ip)

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
        data_agent = execute([AGENT_CONTROL, '-j', '-e', '-i', self.id])

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
        return execute([MANAGE_AGENT, '-j', '-e', self.id])

    def restart(self):
        return execute([AGENT_CONTROL, '-j', '-R', '-u', self.id])

    def remove(self):
        return execute([MANAGE_AGENT, '-j', '-r', self.id])

    def add(self, name, ip):
        if ip.lower() == 'any':
            cmd = [MANAGE_AGENT, '-j', '-a', 'any', '-n', name]
        else:
            cmd = [MANAGE_AGENT, '-j', '-a', ip, '-n', name];

        self.id = execute(cmd)['id']
        return self.id
