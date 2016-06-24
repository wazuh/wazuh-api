#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

ossec_path = '/var/ossec'

manage_agents = '{0}/bin/manage_agents'.format(ossec_path)
agent_control = '{0}/bin/agent_control'.format(ossec_path)
ossec_control = '{0}/bin/ossec-control'.format(ossec_path)
rootcheck_control = '{0}/bin/rootcheck_control'.format(ossec_path)
syscheck_control = '{0}/bin/syscheck_control'.format(ossec_path)

ruleset_py = '{0}/update/ruleset/ossec_ruleset.py'.format(ossec_path)

ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
ossec_log = "{0}/logs/ossec.log".format(ossec_path)
stats_path = '{0}/stats'.format(ossec_path)
rules_path = '{0}/rules'.format(ossec_path)
