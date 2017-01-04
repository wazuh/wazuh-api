#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.database import Connection
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import datetime, timedelta
from hashlib import md5
from base64 import b64encode
from shutil import copyfile, move
from random import randrange
from time import time
from platform import platform
from os import remove, chown, chmod
from pwd import getpwnam
from grp import getgrnam

class Agent:
    """
    OSSEC Agent object.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an agent.

        :param args: 'id' in case it is known, or 'name' and 'ip' to add the agent.
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
        self.sharedSum = None

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
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os, 'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive, 'status': self.status, 'key': self.key, 'sharedSum': self.sharedSum }
        return dictionary

    @staticmethod
    def calculate_status(last_keep_alive):
        """
        Calculates state based on last keep alive
        """
        if last_keep_alive == 0:
            return "Never connected"
        else:
            limit_seconds = 600*3 + 30
            last_date = datetime.strptime(last_keep_alive, '%Y-%m-%d %H:%M:%S')
            difference = (datetime.now() - last_date).total_seconds()

            if difference < limit_seconds:
                return "Active"
            else:
                return "Disconnected"

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

        select = ["id", "name", "ip", "key", "os", "version", "date_add", "last_keepalive", "shared_sum"]

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
            if tuple[8] != None:
                self.sharedSum = tuple[8]

            if self.id != "000":
                self.status = Agent.calculate_status(self.lastKeepAlive)
            else:
                self.status = 'Active'
                self.ip = '127.0.0.1'

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
        if self.sharedSum:
            info['sharedSum'] = self.sharedSum
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
            self.key = b64encode(str_key.encode()).decode()
        else:
            self.key = ""

        return self.key

    def restart(self):
        """
        Restarts the agent.

        :return: Message generated by OSSEC.
        """

        if self.id == "000":
            raise WazuhException(1703)
        else:
            # Check if agent exists and it is active
            agent_info = self.get_basic_information()

            if self.status.lower() != 'active':
                raise WazuhException(1707, '{0} - {1}'.format(self.id, self.status))

            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, self.id)
            oq.close()

        return ret_msg

    def remove(self):
        """
        Deletes the agent.

        :return: Message.
        """

        # Check if authd is running
        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] == 'running':
            raise WazuhException(1704)

        f_keys_temp = '{0}.tmp'.format(common.client_keys)

        f_tmp = open(f_keys_temp, 'w')
        agent_found = False
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                if self.id == line_data[0] and line_data[1][0] not in ('#!'):
                    f_tmp.write('{0} !{1} {2} {3}\n'.format(line_data[0], line_data[1], line_data[2], line_data[3]))
                    agent_found = True
                else:
                    f_tmp.write(line)
        f_tmp.close()

        if agent_found:
            # Overwrite client.keys
            move(f_keys_temp, common.client_keys)
            root_uid = getpwnam("ossec").pw_uid
            ossec_gid = getgrnam("ossec").gr_gid
            chown(common.client_keys, root_uid, ossec_gid)
            chmod(common.client_keys, 0o640)
        else:
            remove(f_keys_temp)
            raise WazuhException(1701, self.id)

        return 'Agent removed'

    def _add(self, name, ip):
        """
        Adds the agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :return: Agent ID.
        """

        # Check if authd is running
        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] == 'running':
            raise WazuhException(1704)

        # Check if ip or name exist in client.keys
        last_id = 0
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                if line[0] in ('# '):  # starts with # or ' '
                    continue

                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                if line_data[1][0] in ('#!'):  # name starts with # or !
                    continue

                if name == line_data[1]:
                    raise WazuhException(1705, name)
                if ip.lower() != 'any' and ip == line_data[2]:
                    raise WazuhException(1706, ip)

                id = int(line_data[0])
                if last_id < id:
                    last_id = id

        last_id = str(last_id + 1).zfill(3)

        # Tmp file
        f_keys_temp = '{0}.tmp'.format(common.client_keys)
        copyfile(common.client_keys, f_keys_temp)

        # Generate key
        random_number = randrange(1, 999999)
        epoch_time = int(time())
        str1 = "{0}{1}{2}{3}".format(epoch_time, name, random_number, platform())
        random_number = randrange(1, 999999)
        str2 = "{0}{1}{2}".format(ip, last_id, random_number)
        hash1 = md5()
        hash1.update(str1.encode())
        hash2 = md5()
        hash2.update(str2.encode())
        new_key = hash1.hexdigest() + hash2.hexdigest()

        # Write key
        with open(f_keys_temp, 'a') as f_kt:
            f_kt.write('{0} {1} {2} {3}\n'.format(last_id, name, ip, new_key))

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)
        root_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
        chown(common.client_keys, root_uid, ossec_gid)
        chmod(common.client_keys, 0o640)

        self.id = last_id

    @staticmethod
    def get_agents_overview(status="all", offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available agents with basic attributes.

        :param status: Filters by agent status: Active, Disconnected or Never connected.
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
            elif status.lower() == "never connected":
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

            order_str_fields = []
            for i in sort['fields']:
                # Order by status ASC is the same that order by last_keepalive DESC.
                if i == 'status':
                    if sort['order'] == 'asc':
                        str_order = "desc"
                    else:
                        str_order = "asc"
                else:
                    str_order = sort['order']
                order_str_fields.append('{0} {1}'.format(fields[i], str_order))

            if sort['fields']:
                query += ' ORDER BY ' + ','.join(order_str_fields)
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
                data_tuple['status'] = "Active"
                data_tuple['ip'] = '127.0.0.1'
            else:
                data_tuple['status'] = Agent.calculate_status(lastKeepAlive)

            data['items'].append(data_tuple)

        return data

    @staticmethod
    def get_agents_summary():
        """
        Counts the number of agents by status.

        :return: Dictionary with keys: total, Active, Disconnected, Never connected
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

        return {'Total': total, 'Active': active, 'Disconnected': disconnected, 'Never connected': never}

    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.

        :param agent_id: Agent ID of the agent to restart.
        :param restart_all: Restarts all agents.

        :return: Message.
        """

        if restart_all:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
            oq.close()
            return ret_msg
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
