#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rules import Rules
from configuration import Configuration
from manager import Manager
from rootcheck import Rootcheck
from syscheck import Syscheck
from agents import Agents
import re

__all__ = ["Wazuh"]


class Wazuh:
    OSSEC_INIT = '/etc/ossec-init.conf'

    def __init__(self, path='/var/ossec', get_init=False):
        self.path = path

        self.version = None
        self.installation_date = None
        self.type = None
        self.pretty = False

        if get_init:
            self.get_ossec_init()

        self.rules = Rules(self.path)
        self.configuration = Configuration(self.path)
        self.manager = Manager(self.path)
        self.rootcheck = Rootcheck(self.path)
        self.syscheck = Syscheck(self.path)
        self.agents = Agents(self.path)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'path': self.path, 'version': self.version, 'installation_date': self.installation_date, 'type': self.type}

    def get_ossec_init(self):
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
