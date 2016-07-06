#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


class WazuhException(Exception):
    ERRORS = {
        # Wazuh: 1000 - 1099
        1000: 'Wazuh-Python Internal Error',
        1001: 'Error importing module',
        1002: 'Error executing command',
        1003: 'Command output not in json',
        1004: 'Malformed command output ',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',

        # Rule: 1200 - 1299
        1200: 'Error reading rules from ossec.conf',
        1201: 'Error reading rule files',
        1202: 'Argument \'status\' must be: enabled, disabled or all',
        1203: 'Argument \'level\' must be a number or an interval separated by \'-\'',
        1204: 'Operation not implemented',

        # Stats: 1300 - 1399
        1307: 'Invalid parameters',
        1308: 'Couldn\'t open stats file',
        1309: 'Statistics file damaged',

        # Utils: 1400 - 1499
        1400: 'Invalid offset',
        1401: 'Invalid limit',
        1402: 'Invalid order. Order must be \'asc\' or \'desc\'',
        1403: 'Sort field invalid',  # Also, in DB

        # Decoders: 1500 - 1599
        1500: 'Error reading decoders from ossec.conf',
        1501: 'Error reading decoder files',

        # Syscheck: 1600 - 1699
        1600: 'Empty syscheck database for selected agent',

        # Manager:
        # Agents:
        # Rootcheck:

        # Database:
        2000: 'No such database file',

        }

    def __init__(self, code, extra_message=None, cmd_error=False):
        self.code = code
        if not cmd_error:
            if extra_message:
                self.message = "{0}: {1}".format(self.ERRORS[code], extra_message)
            else:
                self.message = "{0}.".format(self.ERRORS[code])
        else:
            self.message = extra_message
