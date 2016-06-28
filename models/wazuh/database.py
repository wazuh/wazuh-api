#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from os.path import isfile
import sqlite3

class Connection:
    '''Represents a connection against a database'''

    def __init__(self):
        '''Constructor'''

        if not isfile(common.database_path):
            raise WazuhException(2000)

        self.__conn = sqlite3.connect(common.database_path)
        self.__cur = self.__conn.cursor()

    def execute(self, query, args):
        '''Execute query'''
        self.__cur.execute(query, args)

    def fetch(self):
        '''Return next tuple'''
        return self.__cur.fetchone()

    def __iter__(self):
        '''Iterating support'''
        return self.__cur.__iter__()
