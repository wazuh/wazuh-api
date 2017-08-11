#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chmod_r, chown_r
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket
from wazuh.database import Connection
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import date, datetime, timedelta
from hashlib import md5, sha1
from base64 import b64encode
from shutil import copyfile, move, copytree
from time import time
from platform import platform
from os import remove, chown, chmod, path, makedirs, rename, urandom, listdir, stat
from pwd import getpwnam
from grp import getgrnam
from time import time, sleep
import requests
import json
import socket
from distutils.version import StrictVersion
try:
    from urllib import urlopen, urlretrieve
except ImportError:
    from urllib.request import urlopen, urlretrieve

class Node:
    """
    Wazuh node object
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an node.
        'id': Node id when it exists
        'node', 'ip', 'user', 'password': Insert a new node

        :param args:   [id | node, ip, user, password].
        :param kwargs: [id | node, ip, user, password].
        """
        self.id = None
        self.node = None
        self.ip = None
        self.password = None
        self.user = None
        self.status = None
        self.last_check = None

        if args:
            if len(args) == 1:
                self.id = args[0]
            elif len(args) == 4:
                self._add(node=args[0], ip=args[1], user=args[2], password=args[3])
            else:
                raise WazuhException(1700)
        elif kwargs:
            if len(kwargs) == 1:
                self.id = kwargs['id']
            elif len(kwargs) == 4:
                self._add(node=kwargs['node'], ip=kwargs['ip'], user=kwargs['user'], password=kwargs['password'])
            else:
                raise WazuhException(1700)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'node': self.node, 'ip': self.ip, 'user': self.user, 'password': self.password, 'status': self.status, 'last_check': self.last_check }

        return dictionary

    @staticmethod
    def add_node(node, ip, user, password):
        """
        Adds a new node to Wazuh Cluster

        :param node: name of the node
        :param ip: IP.
        :param user: User for API
        :param password: Password for API
        :return: Node ID.
        """

        return Node(node=node, ip=ip, user=user, password=password).id

    def _add(self, node, ip, user, password):
        """
        Adds a new node to Wazuh Cluster

        :param node: name of the node
        :param ip: IP.
        :param user: User for API
        :param password: Password for API
        :return: Node ID.
        """

        conn = Connection(common.database_path_cluster)
        conn.execute('''CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY,node TEXT NOT NULL,ip TEXT,user TEXT,password TEXT,status TEXT,last_check TEXT)''')
        conn.commit()

        db_cluster = glob(common.database_path_cluster)
        if not db_cluster:
            raise WazuhException(1600)

        request = {"id": None, "last_check": None, "status": None, "node": node, "ip": ip, "user": user, "password": password}
        request = (None, node, ip, user, password, None, None)
        id = conn.execute('''INSERT INTO nodes(id,node,ip,user,password,last_check,status) VALUES(?,?,?,?,?,?,?)''', request)
        conn.commit()
        self.id = id
        return self

    @staticmethod
    def cluster_nodes(id="all", node="all", ip="all", offset=0, limit=common.database_limit, sort=None, search=None):

        conn = Connection(common.database_path_cluster)
        conn.execute('''CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY,node TEXT NOT NULL,ip TEXT,user TEXT,password TEXT,status TEXT,last_check TEXT)''')
        conn.commit()

        db_cluster = glob(common.database_path_cluster)
        if not db_cluster:
            raise WazuhException(1600)

        # Query
        query = "SELECT {0} FROM nodes"
        fields = {'id': 'id', 'node': 'node', 'ip': 'ip', 'user': 'user', 'password': 'password', 'status': 'status', 'last_check': 'last_check' }
        select = ["id", "node", "ip", "user", "password", "status", "last_check"]
        search_fields = ["id", "node", "ip", "user", "status", "last_check"]
        request = {}

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

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0])
            if tuple[1] != None:
                data_tuple['node'] = tuple[1]
            if tuple[2] != None:
                data_tuple['ip'] = tuple[2]
            if tuple[3] != None:
                data_tuple['user'] = tuple[3]
            if tuple[4] != None:
                data_tuple['password'] = tuple[4]
            if tuple[5] != None:
                data_tuple['status'] = tuple[5]
            if tuple[6] != None:
                data_tuple['last_check'] = tuple[6]

            data['items'].append(data_tuple)

        return data


    @staticmethod
    def send_request_api(url, auth, verify, type):
        error = 0
        try:
            r = requests.get(url, auth=auth, params=None, verify=verify)
        except requests.exceptions.Timeout as e:
            data = str(e)
            error = 1
        except requests.exceptions.TooManyRedirects as e:
            data = str(e)
            error = 2
        except requests.exceptions.RequestException as e:
            data = str(e)
            error = 3
        except Exception as e:
            data = str(e)
            error = 4

        if error == 0:
            if type == "json":
                try:
                    data = json.loads(r.text)
                except Exception as e:
                    data = str(e)
                    error = 5
            else:
                data = r.text
        return (error, data)

    @staticmethod
    def sync():
        """
        Sync this node with others
        :return: Files synced.
        """

        #Get its own files status
        own_items = manager.get_files()

        #Get other nodes files
        cluster = Node()
        nodes = cluster.cluster_nodes()["items"]


        pushed_files = []
        info = []
        for node in nodes:
            # Configuration
            base_url = "http://{0}:55000".format(node["ip"])
            auth = requests.auth.HTTPBasicAuth(node["user"], node["password"])
            verify = False
            url = '{0}{1}'.format(base_url, "/manager/files")
            error, response = Node.send_request_api(url, auth, verify, "json")

            discard_list = []
            download_list = []
            sychronize_list = []
            error_list = []

            if error:
                error_list.append({'api_error': response, "code": error})
                continue

            # Items - files
            their_items = response["data"]

            remote_files = response['data'].keys()
            local_files = own_items.keys()

            missing_files_locally = set(remote_files) - set(local_files)
            missing_files_remotely =  set(local_files) - set(remote_files)
            shared_files = set(local_files).intersection(remote_files)




            # Shared files
            for filename in shared_files:

                local_file_time = datetime.strptime(own_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S.%f")
                local_file = {
                    "name": filename,
                    "md5": own_items[filename]["md5"],
                    "modification_time": own_items[filename]["modification_time"]
                }

                remote_file_time = datetime.strptime(their_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S.%f")
                remote_file = {
                    "name": filename,
                    "md5": their_items[filename]["md5"],
                    "modification_time": their_items[filename]["modification_time"]
                }

                conditions = { "different_md5": False, "remote_time_higher": False}

                if remote_file["md5"] != local_file["md5"]:
                    conditions["different_md5"] = True
                if remote_file_time > local_file_time:
                    conditions["remote_time_higher"] = True

                check_item = {
                    "file": remote_file,
                    "conditions": conditions,
                    "updated": False,
                    "node": node["node"]
                }

                if conditions["different_md5"] and conditions["remote_time_higher"]:
                    download_list.append(check_item)
                else:
                    discard_list.append(check_item)

            # Missing files
            for filename in missing_files_locally:

                remote_file = {
                    "name": filename,
                    "md5": their_items[filename]["md5"],
                    "modification_time": their_items[filename]["modification_time"],
                    "conditions": { "missing": True}
                }


                download_list.append(remote_file)

            # Download


            for item in download_list:
                try:
                    # Downloading files from each node and update
                    base_url = "http://{0}:55000".format(node["ip"])

                    url = '{0}{1}'.format(base_url, "/manager/files?download="+item["name"])

                    error, downloaded_file = Node.send_request_api(url, auth, verify, "text")
                    if error:
                        error_list.append({'item': item, 'reason': downloaded_file})
                        continue

                    # fix me!
                    # dest_file = open(common.ossec_path+item["name"],"w")
                    dest_file = open(item["name"],"w")
                    dest_file.write(downloaded_file)
                    dest_file.close()
                except Exception as e:
                    error_list.append({'item': item, 'reason': str(e)})
                    continue


                item["updated"] = True
                sychronize_list.append(item)

        #print check_list
        final_output = {
            'discard': discard_list,
            'error': error_list,
            'updated': sychronize_list
        }

        return final_output
