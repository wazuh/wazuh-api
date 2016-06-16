#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


class WazuhException(Exception):
    ERRORS = {
        # Wazuh: 1000 - 1099
        1000: 'Wazuh-Python Internal Error',
        1001: 'Error importing module',

        # Configuration: 1100 - 1199
        1100: 'Error checking configuration',

        # Rules: 1200 - 1299
        1200: 'Error reading rules from ossec.conf',
        1201: 'Error reading rule files',
        1202: 'Argument \'status\' must be: enabled, disabled or all',

        # Stats: 1300 - 1399
        1307: 'Invalid parameters',
        1308: 'Couldn\'t open stats file',
        1309: 'Statistics file damaged'

        # Manager:
        # Agents:
        # Syscheck:
        # Rootcheck

        }

    def __init__(self, code, extra_message=None):
        self.code = code
        if extra_message:
            self.message = "{0}: {1}".format(self.ERRORS[code], extra_message)
        else:
            self.message = "{0}.".format(self.ERRORS[code], extra_message)
