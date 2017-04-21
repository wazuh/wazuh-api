#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from os.path import isfile
from distutils.version import LooseVersion
import sqlite3

# Check SQL compatibility: >= 3.7.0.0
if LooseVersion(sqlite3.sqlite_version) < LooseVersion('3.7.0.0'):
    raise WazuhException(2001, str(sqlite3.sqlite_version))


class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path_global):
        """
        Constructor
        """
        self.db_path = db_path

        if not isfile(db_path):
            raise WazuhException(2000)

        self.__conn = sqlite3.connect(db_path)
        self.__cur = self.__conn.cursor()

    def __iter__(self):
        """
        Iterating support
        """
        return self.__cur.__iter__()

    def begin(self):
        """
        Begin transaction
        """
        self.__cur.execute('BEGIN')

    def commit(self):
        """
        Commit changes
        """
        self.__conn.commit()

    def execute(self, query, *args):
        """
        Execute query

        :param query: Query string.
        :param args: Query values.
        """
        if args:
            self.__cur.execute(query, *args)
        else:
            self.__cur.execute(query)

    def fetch(self):
        """
        Return next tuple
        """
        return self.__cur.fetchone()

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and desfragment
        """
        self.__cur.execute('VACUUM')
