#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh import common

__all__ = ["Manager"]

class Manager:

    @staticmethod
    def status():
        return execute([common.ossec_control, '-j', 'status'])

    @staticmethod
    def start():
        return execute([common.ossec_control, '-j', 'start'])

    @staticmethod
    def stop():
        return execute([common.ossec_control, '-j', 'stop'])

    @staticmethod
    def restart():
        return execute([common.ossec_control, '-j', 'restart'])

    @staticmethod
    def update_ruleset(type='both', force=False):
        args = [common.ruleset_py, '--json', '--restart']

        if type == 'rules':
            args.append('--rules')
        elif type == 'rootchecks':
            args.append('--rootchecks')

        if force:
            args.append('--force-update')

        return execute(args)
