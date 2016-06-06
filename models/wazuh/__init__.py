#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rules import Rules
from configuration import Configuration
from stats import Stats
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
        self.stats = Stats(self.path)

    def __str__(self):
        dictionary = {'path': self.path, 'version': self.version, 'installation_date': self.installation_date, 'type': self.type}
        return str(dictionary)

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


def main():
    print("Wazuh HIDS Library")
