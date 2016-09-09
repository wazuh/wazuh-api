#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.database import Connection
from glob import glob
from datetime import datetime, timedelta
from base64 import b64encode

class Agent:
    """
    OSSEC Agent object.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an agent.

        :param args: 'AgentID' in case it is known, or 'name' and 'ip' to add the agent.
        """
        self.id = None
        self.name = None
        self.ip = None
        self.internal_key = None
        self.os = None
        self.version = None
        self.dateAdd = None
        self.lastKeepAlive = None
        self.status = None
        self.key = None

        if len(args) == 1:
            self.id = args[0]
        elif 'id' in kwargs:
            self.id = kwargs['id']
        elif len(args) == 2:
            self._add(args[0], args[1])
        elif 'ip' in kwargs and 'name' in kwargs:
            self._add(kwargs['name'], kwargs['ip'])
        else:
            raise WazuhException(1700)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os, 'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive, 'status': self.status, 'key': self.key }
        return dictionary

    @staticmethod
    def calculate_status(last_keep_alive):
        """
        Calculates state based on last keep alive
        """
        if last_keep_alive == 0:
            return "neverConnected"
        else:
            limit_seconds = 600*3 + 30
            last_date = datetime.strptime(last_keep_alive, '%Y-%m-%d %H:%M:%S')
            difference = (datetime.now() - last_date).total_seconds()

            if difference < limit_seconds:
                return "active"
            else:
                return "disconnected"

    def _load_info_from_DB(self):
        """
        Gets attributes of existing agent.
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query = "SELECT {0} FROM agent WHERE id = :id"
        request = {'id': self.id}

        select = ["id", "name", "ip", "key", "os", "version", "date_add", "last_keepalive"]

        conn.execute(query.format(','.join(select)), request)

        no_result = True
        for tuple in conn:
            no_result = False
            data_tuple = {}

            if tuple[0] != None:
                self.id = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                self.name = tuple[1]
            if tuple[2] != None:
                self.ip = tuple[2]
            if tuple[3] != None:
                self.internal_key = tuple[3]
            if tuple[4] != None:
                self.os = tuple[4]
            if tuple[5] != None:
                self.version = tuple[5]
            if tuple[6] != None:
                self.dateAdd = tuple[6]
            if tuple[7] != None:
                self.lastKeepAlive = tuple[7]
            else:
                self.lastKeepAlive = 0

            if self.id != "000":
                self.status = Agent.calculate_status(self.lastKeepAlive)
            else:
                self.status = 'active'

        if no_result:
            raise WazuhException(1701, self.id)

    def get_basic_information(self):
        """
        Gets public attributes of existing agent.
        """
        self._load_info_from_DB()

        info = {}

        if self.id:
            info['id'] = self.id
        if self.name:
            info['name'] = self.name
        if self.ip:
            info['ip'] = self.ip
        #if self.internal_key:
        #    info['internal_key'] = self.internal_key
        if self.os:
            info['os'] = self.os
        if self.version:
            info['version'] = self.version
        if self.dateAdd:
            info['dateAdd'] = self.dateAdd
        if self.lastKeepAlive:
            info['lastKeepAlive'] = self.lastKeepAlive
        if self.status:
            info['status'] = self.status
        #if self.key:
        #    info['key'] = self.key

        return info

    def get_key(self):
        """
        Gets agent key.

        :return: Agent key.
        """

        self._load_info_from_DB()
        if self.id != "000":
            str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.ip, self.internal_key)
            self.key = b64encode(str_key)
        else:
            self.key = ""

        return self.key

    def restart(self):
        """
        Restarts the agent.

        :return: Message generated by OSSEC.
        """

        return execute([common.agent_control, '-j', '-R', '-u', self.id])

    def remove(self):
        """
        Deletes the agent.

        :return: Message generated by OSSEC.
        """
        return execute([common.manage_agents, '-j', '-r', self.id])

    def _add(self, name, ip):
        """
        Adds the agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :return: Agent ID.
        """

        if ip.lower() == 'any':
            cmd = [common.manage_agents, '-j', '-a', 'any', '-n', name]
        else:
            cmd = [common.manage_agents, '-j', '-a', ip, '-n', name]

        self.id = execute(cmd)['id']

    @staticmethod
    def get_agents_overview(status="all", offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available agents with basic attributes.

        :param status: Filters by agent status: active, disconnected or neverConnected.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query = "SELECT {0} FROM agent"
        fields = {'id': 'id', 'name': 'name', 'ip': 'ip', 'status': 'last_keepalive'}
        sort_by_status_manually = False
        select = ["id", "name", "ip", "last_keepalive"]
        request = {}

        if status != "all":
            limit_seconds = 600*3 + 30
            result = datetime.now() - timedelta(seconds=limit_seconds)
            request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')

            if status.lower() == 'active':
                query += ' AND (last_keepalive >= :time_active or id = 0)'
            elif status.lower() == 'disconnected':
                query += ' AND last_keepalive < :time_active'
            elif status.lower() == "neverconnected":
                query += ' AND last_keepalive IS NULL AND id != 0'

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " OR ".join(x + ' LIKE :search' for x in ('id', 'name', 'ip')) + " )"
            request['search'] = '%{0}%'.format(search['value'])

        if "FROM agent AND" in query:
            query = query.replace("FROM agent AND", "FROM agent WHERE")

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            allowed_sort_fields = fields.keys()
            for sf in sort['fields']:
                if sf not in allowed_sort_fields:
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sf))

            if 'status' in sort['fields']:
                sort_by_status_manually = True
                sort['fields'].remove('status')

            if sort['fields']:
                query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
        else:
            query += ' ORDER BY id ASC'

        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            data_tuple = {}

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                data_tuple['name'] = tuple[1]
            if tuple[2] != None:
                data_tuple['ip'] = tuple[2]

            if tuple[3] != None:
                lastKeepAlive = tuple[3]
            else:
                lastKeepAlive = 0

            if data_tuple['id'] == "000":
                data_tuple['status'] = "active"
            else:
                data_tuple['status'] = Agent.calculate_status(lastKeepAlive)

            data['items'].append(data_tuple)

        if sort_by_status_manually:
            data['items'] = sort_array(data['items'], ['status'], sort['order'])

        return data

    @staticmethod
    def get_agents_summary():
        """
        Counts the number of agents by status.

        :return: Dictionary with keys: total, active, disconnected, neverConnected
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query_all = "SELECT COUNT(*) FROM agent"

        query = "SELECT COUNT(*) FROM agent WHERE {0}"
        request = {}
        query_active = query.format('(last_keepalive >= :time_active or id = 0)')
        query_disconnected = query.format('last_keepalive < :time_active')
        query_never = query.format('last_keepalive IS NULL AND id != 0')

        limit_seconds = 600*3 + 30
        result = datetime.now() - timedelta(seconds=limit_seconds)
        request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')

        conn.execute(query_all)
        total = conn.fetch()[0]

        conn.execute(query_active, request)
        active = conn.fetch()[0]

        conn.execute(query_disconnected, request)
        disconnected = conn.fetch()[0]

        conn.execute(query_never, request)
        never = conn.fetch()[0]

        return {'total': total, 'active': active, 'disconnected': disconnected, 'neverConnected': never}

    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.

        :param agent_id: Agent ID of the agent to restart.
        :param restart_all: Restarts all agents.

        :return: Message generated by OSSEC.
        """

        if restart_all:
            return execute([common.agent_control, '-j', '-R', '-a'])
        else:
            return Agent(agent_id).restart()

    @staticmethod
    def get_agent(agent_id):
        """
        Gets an existing agent.

        :param agent_id: Agent ID.
        :return: The agent.
        """

        return Agent(agent_id).get_basic_information()

    @staticmethod
    def get_agent_key(agent_id):
        """
        Get the key of an existing agent.

        :param agent_id: Agent ID.
        :return: Agent key.
        """

        return Agent(agent_id).get_key()

    @staticmethod
    def remove_agent(agent_id):
        """
        Removes an existing agent.

        :param agent_id: Agent ID.
        :return: Message generated by OSSEC.
        """

        return Agent(agent_id).remove()

    @staticmethod
    def add_agent(name, ip='any'):
        """
        Adds a new agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :return: Agent ID.
        """

        return Agent(name, ip).id
