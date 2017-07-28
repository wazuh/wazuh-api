#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chmod_r
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket
from wazuh.database import Connection
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import date, datetime, timedelta
from hashlib import md5
from base64 import b64encode
from shutil import copyfile, move
from time import time
from platform import platform
from os import remove, chown, chmod, path, makedirs, rename, urandom
from pwd import getpwnam
from grp import getgrnam

class Agent:
    """
    OSSEC Agent object.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an agent.
        'id': When the agent exists
        'name' and 'ip': Add an agent (generate id and key automatically)
        'name', 'ip' and 'force': Add an agent (generate id and key automatically), removing old agent with same IP if disconnected since <force> seconds.
        'name', 'ip', 'id', 'key': Insert an agent with an existent id and key
        'name', 'ip', 'id', 'key', 'force': Insert an agent with an existent id and key, removing old agent with same IP if disconnected since <force> seconds.

        :param args:   [id | name, ip | name, ip, force | name, ip, id, key | name, ip, id, key, force].
        :param kwargs: [id | name, ip | name, ip, force | name, ip, id, key | name, ip, id, key, force].
        """
        self.id = None
        self.name = None
        self.ip = None
        self.internal_key = None
        self.os = {}
        self.version = None
        self.dateAdd = None
        self.lastKeepAlive = None
        self.status = None
        self.key = None
        self.sharedSum = None

        if args:
            if len(args) == 1:
                self.id = args[0]
            elif len(args) == 2:
                self._add(name=args[0], ip=args[1])
            elif len(args) == 3:
                self._add(name=args[0], ip=args[1], force=args[2])
            elif len(args) == 4:
                self._add(name=args[0], ip=args[1], id=args[2], key=args[3])
            elif len(args) == 5:
                self._add(name=args[0], ip=args[1], id=args[2], key=args[3], force=args[4])
            else:
                raise WazuhException(1700)
        elif kwargs:
            if len(kwargs) == 1:
                self.id = kwargs['id']
            elif len(kwargs) == 2:
                self._add(name=kwargs['name'], ip=kwargs['ip'])
            elif len(kwargs) == 3:
                self._add(name=kwargs['name'], ip=kwargs['ip'], force=kwargs['force'])
            elif len(kwargs) == 4:
                self._add(name=kwargs['name'], ip=kwargs['ip'], id=kwargs['id'], key=kwargs['key'])
            elif len(kwargs) == 5:
                self._add(name=kwargs['name'], ip=kwargs['ip'], id=kwargs['id'], key=kwargs['key'], force=kwargs['force'])
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

        select = ["id", "name", "ip", "key", "version", "date_add", "last_keepalive", "shared_sum", "os_name", "os_version", "os_major", "os_minor", "os_codename", "os_build", "os_platform", "os_uname"]

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
                self.version = tuple[4]
            if tuple[5] != None:
                self.dateAdd = tuple[5]

            if tuple[6] != None:
                self.lastKeepAlive = tuple[6]
            else:
                self.lastKeepAlive = 0

            if tuple[7] != None:
                self.sharedSum = tuple[7]

            if tuple[8] != None:
                self.os['name'] = tuple[8]
            if tuple[9] != None:
                self.os['version'] = tuple[9]
            if tuple[10] != None:
                self.os['major'] = tuple[10]
            if tuple[11] != None:
                self.os['minor'] = tuple[11]
            if tuple[12] != None:
                self.os['codename'] = tuple[12]
            if tuple[13] != None:
                self.os['build'] = tuple[13]
            if tuple[14] != None:
                self.os['platform'] = tuple[14]
            if tuple[15] != None:
                self.os['uname'] = tuple[15]

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
            os_no_empty = dict((k, v) for k, v in self.os.iteritems() if v)
            if os_no_empty:
                info['os'] = os_no_empty
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

    def remove(self, backup=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] != 'running':
            data = self._remove_manual(backup)
        else:
            data = self._remove_authd()

        return data

    def _remove_authd(self):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        msg = { "function": "remove", "arguments": { "id": str(self.id) } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        # Get info from DB
        self._load_info_from_DB()

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

        if not agent_found:
            remove(f_keys_temp)
            raise WazuhException(1701, self.id)

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)
        root_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
        chown(common.client_keys, root_uid, ossec_gid)
        chmod(common.client_keys, 0o640)

        # Remove rid file
        rids_file = '{0}/queue/rids/{1}'.format(common.ossec_path, self.id)
        if path.exists(rids_file):
            remove(rids_file)

        if not backup:
            # Remove agent files
            agent_files = []
            agent_files.append('{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/rids/{1}'.format(common.ossec_path, self.id))
            agent_files.append('{0}/var/db/agents/{1}-{2}.db'.format(common.ossec_path, self.id, self.name))
            agent_files.append('{0}/var/db/agents/{1}-{2}.db-wal'.format(common.ossec_path, self.id, self.name))
            agent_files.append('{0}/var/db/agents/{1}-{2}.db-shm'.format(common.ossec_path, self.id, self.name))

            for agent_file in agent_files:
                if path.exists(agent_file):
                    remove(agent_file)
        else:
            # Create backup directory
            # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
            date_part = date.today().strftime('%Y/%b/%d')
            main_agent_backup_dir = '{0}/backup/agents/{1}/{2}-{3}-{4}'.format(common.ossec_path, date_part, self.id, self.name, self.ip)
            agent_backup_dir = main_agent_backup_dir

            not_agent_dir = True
            i = 0
            while not_agent_dir:
                if path.exists(agent_backup_dir):
                    i += 1
                    agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                else:
                    makedirs(agent_backup_dir)
                    chmod_r(agent_backup_dir, 0o750)
                    not_agent_dir = False

            # Move agent file
            agent_files = []
            agent_files.append(['{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip), '{0}/agent-info'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip), '{0}/rootcheck'.format(agent_backup_dir)])

            for agent_file in agent_files:
                if path.exists(agent_file[0]) and not path.exists(agent_file[1]):
                    rename(agent_file[0], agent_file[1])

        return 'Agent deleted successfully.'

    def _add(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] != 'running':
            data = self._add_manual(name, ip, id, key, force)
        else:
            data = self._add_authd(name, ip, id, key, force)

        return data

    def _add_authd(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "force": force } }
            else:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "id": id, "key": key, "force": force } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        self.id = data['id']

    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC manually.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                if not line.strip():  # ignore empty lines
                    continue

                if line[0] in ('# '):  # starts with # or ' '
                    continue

                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                line_id = int(line_data[0])
                if last_id < line_id:
                    last_id = line_id

                if line_data[1][0] in ('#!'):  # name starts with # or !
                    continue

                check_remove = 0
                if id and id == line_data[0]:
                    raise WazuhException(1708, id)
                if name == line_data[1]:
                    if force < 0:
                        raise WazuhException(1705, name)
                    else:
                        check_remove = 1
                if ip != 'any' and ip == line_data[2]:
                    if force < 0:
                        raise WazuhException(1706, ip)
                    else:
                        check_remove = 2

                if check_remove:
                    if force == 0 or Agent.check_if_delete_agent(line_data[0], force):
                        Agent.remove_agent(line_data[0], backup=True)
                    else:
                        if check_remove == 1:
                            raise WazuhException(1705, name)
                        else:
                            raise WazuhException(1706, ip)

        if not id:
            agent_id = str(last_id + 1).zfill(3)
        else:
            agent_id = id

        if not key:
            # Generate key
            epoch_time = int(time())
            str1 = "{0}{1}{2}".format(epoch_time, name, platform())
            str2 = "{0}{1}".format(ip, agent_id)
            hash1 = md5(str1.encode())
            hash1.update(urandom(64))
            hash2 = md5(str2.encode())
            hash1.update(urandom(64))
            agent_key = hash1.hexdigest() + hash2.hexdigest()
        else:
            agent_key = key

        # Tmp file
        f_keys_temp = '{0}.tmp'.format(common.client_keys)
        copyfile(common.client_keys, f_keys_temp)

        # Write key
        with open(f_keys_temp, 'a') as f_kt:
            f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)
        root_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
        chown(common.client_keys, root_uid, ossec_gid)
        chmod(common.client_keys, 0o640)

        self.id = agent_id

    @staticmethod
    def get_agents_overview(status="all", os_platform="all", os_version="all", offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available agents with basic attributes.

        :param status: Filters by agent status: Active, Disconnected or Never connected.
        :param os_platform: Filters by OS platform.
        :param os_version: Filters by OS version.
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
        fields = {'id': 'id', 'name': 'name', 'ip': 'ip', 'status': 'last_keepalive', 'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform' }
        select = ["id", "name", "ip", "last_keepalive", "os_name", "os_version", "os_platform"]
        search_fields = ["id", "name", "ip", "os_name", "os_version", "os_platform"]
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

        if os_platform != "all":
            request['os_platform'] = os_platform
            query += ' AND os_platform = :os_platform'
        if os_version != "all":
            request['os_version'] = os_version
            query += ' AND os_version = :os_version'

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " OR ".join(x + ' LIKE :search' for x in search_fields) + " )"
            request['search'] = '%{0}%'.format(search['value'])

        if "FROM agent AND" in query:
            query = query.replace("FROM agent AND", "FROM agent WHERE")

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = []
                for i in sort['fields']:
                    # Order by status ASC is the same that order by last_keepalive DESC.
                    if i == 'status':
                        str_order = "desc" if sort['order'] == 'asc' else "asc"
                        order_str_field = '{0} {1}'.format(fields[i], str_order)
                    # Order by version is order by major and minor
                    elif i == 'os.version':
                        order_str_field = "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(sort['order'])
                    else:
                        order_str_field = '{0} {1}'.format(fields[i], sort['order'])

                    order_str_fields.append(order_str_field)

                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY id {0}'.format(sort['order'])
        else:
            query += ' ORDER BY id ASC'

        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            data_tuple = {}
            os = {}

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

            if tuple[4] != None:
                os['name'] = tuple[4]
            if tuple[5] != None:
                os['version'] = tuple[5]
            if tuple[6] != None:
                os['platform'] = tuple[6]

            if os:
                os_no_empty = dict((k, v) for k, v in os.iteritems() if v)
                if os_no_empty:
                    data_tuple['os'] = os_no_empty

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
    def get_os_summary(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available OS.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Init query
        query = "SELECT DISTINCT {0} FROM agent WHERE os_platform IS NOT null AND os_platform != ''"
        fields = {'os.platform': 'os_platform'}  # field: db_column
        select = ["os_platform"]
        request = {}

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " ( os_platform LIKE :search )"
            request['search'] = '%{0}%'.format(search['value'])

        # Count
        conn.execute(query.format('COUNT(DISTINCT os_platform)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['`{0}` {1}'.format(fields[i], sort['order']) for i in sort['fields']]
                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY os_platform {0}'.format(sort['order'])
        else:
            query += ' ORDER BY os_platform ASC'

        # OFFSET - LIMIT
        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        conn.execute(query.format(','.join(select)), request)

        data['items'] = []
        for tuple in conn:
            if tuple[0] != None:
                data['items'].append(tuple[0])

        return data

    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.

        :param agent_id: Agent ID of the agent to restart. Can be a list of ID's.
        :param restart_all: Restarts all agents.

        :return: Message.
        """

        if restart_all:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
            oq.close()
            return ret_msg
        else:
            ids = list()
            if isinstance(agent_id, basestring):
                try:
                    Agent(agent_id).restart()
                except Exception as e:
                    ids.append(id)
            else:
                for id in agent_id:
                    try:
                        Agent(id).restart()
                    except Exception as e:
                        ids.append(id)
            if not ids:
                message = 'All selected agents were restarted'
            else:
                message = 'Some agents were not restarted'

            return {'msg':message, 'ids':ids}

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
    def remove_agent(agent_id, backup=False):
        """
        Removes an existing agent.

        :param agent_id: Agent ID. Can be a list of ID's.
        :param backup: Create backup before removing the agent.
        :return: Message generated by OSSEC.
        """
        ids = list()
        if isinstance(agent_id, basestring):
            try:
                Agent(agent_id).remove(backup)
            except Exception as e:
                ids.append(id)
        else:
            for id in agent_id:
                try:
                    Agent(id).remove(backup)
                except Exception as e:
                    ids.append(id)

        if not ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        return {'msg':message, 'ids':ids}


    @staticmethod
    def add_agent(name, ip='any', force=-1):
        """
        Adds a new agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        return Agent(name=name, ip=ip, force=force).id

    @staticmethod
    def insert_agent(name, id, key, ip='any', force=-1):
        """
        Create a new agent providing the id, name, ip and key to the Manager.

        :param id: id of the new agent.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param key: name of the new agent.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        return Agent(name=name, ip=ip, id=id, key=key, force=force).id

    @staticmethod
    def check_if_delete_agent(id, seconds):
        """
        Check if we should remove an agent: if time from last connection is greater thant <seconds>.

        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False

        agent_info = Agent(id=id).get_basic_information()

        if 'lastKeepAlive' in agent_info:
            if agent_info['lastKeepAlive'] == 0:
                remove_agent = True
            else:
                last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                difference = (datetime.now() - last_date).total_seconds()
                if difference >= seconds:
                    remove_agent = True

        return remove_agent
