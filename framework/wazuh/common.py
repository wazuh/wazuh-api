#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

def set_paths_based_on_ossec(o_path='/var/ossec'):
    """
    Set paths based on ossec location.
    :param o_path: OSSEC Path, by default it is '/var/ossec'.
    :return:
    """

    global ossec_path
    ossec_path = o_path

    global ossec_conf
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)

    global ossec_log
    ossec_log = "{0}/logs/ossec.log".format(ossec_path)

    global client_keys
    client_keys = '{0}/etc/client.keys'.format(ossec_path)

    global stats_path
    stats_path = '{0}/stats'.format(ossec_path)

    global rules_path
    rules_path = '{0}/rules'.format(ossec_path)

    global database_path
    database_path = ossec_path + '/var/db'

    global database_path_global
    database_path_global = database_path + '/global.db'

    global database_path_agents
    database_path_agents = database_path + '/agents'


# Common variables
database_limit = 500

# Common variables based on ossec path (/var/ossec by default)
set_paths_based_on_ossec()
