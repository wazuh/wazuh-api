#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import common
import re

"""
Wazuh HIDS Python package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Wazuh is a python package to manage OSSEC.

"""


class Wazuh:
    """
    Basic class to set up OSSEC directories
    """

    OSSEC_INIT = '/etc/ossec-init.conf'

    def __init__(self, get_init=False):
        """
        Initialize basic information and directories. By default OSSEC path is /var/ossec.
        :param get_init: Get information from /etc/ossec-init.conf.
        :return:
        """

        self.version = None
        self.installation_date = None
        self.type = None
        self.path = '/var/ossec'

        if get_init:
            self.get_ossec_init()

        common.ossec_path = self.path

        common.manage_agents = '{0}/bin/manage_agents'.format(self.path)
        common.agent_control = '{0}/bin/agent_control'.format(self.path)
        common.ossec_control = '{0}/bin/ossec-control'.format(self.path)
        common.rootcheck_control = '{0}/bin/rootcheck_control'.format(self.path)
        common.syscheck_control = '{0}/bin/syscheck_control'.format(self.path)

        common.ruleset_py = '{0}/update/ruleset/ossec_ruleset.py'.format(self.path)

        common.ossec_conf = "{0}/etc/ossec.conf".format(self.path)
        common.ossec_log = "{0}/logs/ossec.log".format(self.path)
        common.stats_path = '{0}/stats'.format(self.path)
        common.rules_path = '{0}/rules'.format(self.path)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'path': self.path, 'version': self.version, 'installation_date': self.installation_date, 'type': self.type}

    def get_ossec_init(self):
        """
        Gets information from /etc/ossec-init.conf.

        :return: ossec-init.conf as dictionary
        """
        with open(self.OSSEC_INIT, 'r') as f:

            line_regex = re.compile('(^\w+)="(.+)"')
            for line in f:
                match = line_regex.match(line)
                if match and len(match.groups()) == 2:
                    key = match.group(1).lower()
                    if key == "wazuh_version":
                        self.version = match.group(2)
                    elif key == "directory":
                        self.path = match.group(2)
                    elif key == "date":
                        self.installation_date = match.group(2)
                    elif key == "type":
                        self.type = match.group(2)
        return self.to_dict()


def main():
    print("Wazuh HIDS Library")
