#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, previous_month, cut_array
from wazuh import common
from datetime import datetime
import re

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

    @staticmethod
    def get_ruleset_backups():
        args = [common.ruleset_py, '--json', '--backups', 'list']

        return execute(args)['list']

    @staticmethod
    def restore_ruleset_backups(date):
        args = [common.ruleset_py, '--json', '--backups', date, '-s']

        return execute(args)

    @staticmethod
    def __get_ossec_log_category(log):
        regex_category = re.compile("^\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d\s(\S+):\s")

        match = re.search(regex_category, log)

        if match:
            category = match.group(1)

            if "rootcheck" in category:  # Unify rootcheck category
                category = "ossec-rootcheck/rootcheck"

            if "(" in category:  # Remove ()
                category = re.sub("\(\d\d\d\d\)", "", category)
        else:
            return None

        return category

    @staticmethod
    def ossec_log(type_log='error', category='all', months=3, offset=0, limit=0):
        logs = []

        first_date = previous_month(months)
        statfs_error = "ERROR: statfs('******') produced error: No such file or directory"

        with open(common.ossec_log) as f:
            for line in f:
                log_date = datetime.strptime(line[:10], '%Y/%m/%d')

                if log_date < first_date:
                    continue

                if category != 'all':
                    log_category = Manager.__get_ossec_log_category(line)

                    if log_category:
                        if category != log_category:
                            continue
                    else:
                        continue

                line = line.replace('\n', '')
                if type_log == 'all':
                    logs.append(line)
                elif type_log == 'error' and "error:" in line.lower():
                    if "ERROR: statfs(" in line:
                        if statfs_error in logs:
                            continue
                        else:
                            logs.append(statfs_error)
                    else:
                        logs.append(line)
                elif type_log == 'info' and "error:" not in line.lower():
                    logs.append(line)

        return {'items': cut_array(sorted(logs, reverse=True), offset, limit), 'totalItems': len(logs)}

    @staticmethod
    def ossec_log_summary(months=3):
        categories = {}

        first_date = previous_month(months)

        with open(common.ossec_log) as f:

            for line in f:

                log_date = datetime.strptime(line[:10], '%Y/%m/%d')

                if log_date < first_date:
                    continue

                category = Manager.__get_ossec_log_category(line)

                if category:
                    if category in categories:
                        categories[category]['total'] += 1
                    else:
                        categories[category] = {'total': 1, 'info': 0, 'error': 0}

                    if "error" in line.lower():
                        categories[category]['error'] += 1
                    else:
                        categories[category]['info'] += 1
                else:
                    continue
        return categories
