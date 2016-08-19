#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import common
from wazuh.exception import WazuhException
import re

"""
Wazuh HIDS Python package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wazuh is a python package to manage OSSEC.

"""

__version__ = '0.1'

class Wazuh:
    """
    Basic class to set up OSSEC directories
    """

    OSSEC_INIT = '/etc/ossec-init.conf'

    def __init__(self, ossec_path='/var/ossec', get_init=False):
        """
        Initialize basic information and directories.
        :param ossec_path: OSSEC Path. By default it is /var/ossec.
        :param get_init: Get information from /etc/ossec-init.conf.
        :return:
        """

        self.version = None
        self.installation_date = None
        self.type = None
        self.path = ossec_path

        if get_init:
            self.get_ossec_init()

        common.set_paths_based_on_ossec(self.path)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'path': self.path, 'version': self.version, 'installation_date': self.installation_date, 'type': self.type}

    def get_ossec_init(self):
        """
        Gets information from /etc/ossec-init.conf.

        :return: ossec-init.conf as dictionary
        """

        try:
            with open(self.OSSEC_INIT, 'r') as f:
                line_regex = re.compile('(^\w+)="(.+)"')
                for line in f:
                    match = line_regex.match(line)
                    if match and len(match.groups()) == 2:
                        key = match.group(1).lower()
                        if key == "wazuh_version":
                            self.version = match.group(2)
                        elif key == "directory":
                            # Read 'directory' when ossec_path (__init__) is set by default.
                            # It could mean that get_init is True and ossec_path is not used.
                            if self.path == '/var/ossec':
                                self.path = match.group(2)
                        elif key == "date":
                            self.installation_date = match.group(2)
                        elif key == "type":
                            self.type = match.group(2)
        except:
            raise WazuhException(1005, self.OSSEC_INIT)

        return self.to_dict()


def main():
    print("Wazuh HIDS Library")
