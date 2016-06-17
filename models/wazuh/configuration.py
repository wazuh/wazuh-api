#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Configuration

import xml.etree.ElementTree
import subprocess
import os
from xml.etree.ElementTree import fromstring
from wazuh.exception import WazuhException

__all__ = ["Configuration"]


import_problem = None

try:
    from xmljson import gdata as xml_json
except Exception as e:
    import_problem = e


def merge_json_array(json_array):
    if isinstance(json_array, list):
        new_json = {}
        for element in json_array:
            new_json.update(element)
        return new_json
    return json_array


def process_ossecconf(json_conf):

    for element in json_conf:
        if not isinstance(json_conf[element], list):
            for item in json_conf[element]:
                if not isinstance(json_conf[element][item], list):
                    if '$t' in json_conf[element][item]:
                        json_conf[element][item] = json_conf[element][item]['$t']
                else:
                    clean_list = []
                    for i in range(len(json_conf[element][item])):
                        if not isinstance(json_conf[element][item][i], list):
                            if '$t' in json_conf[element][item][i]:
                                clean_list.insert(len(clean_list), json_conf[element][item][i]['$t'])
                    json_conf[element][item] = clean_list
        else:
            for i in range(len(json_conf[element])):
                if not isinstance(json_conf[element][i], list):
                    for item in json_conf[element][i]:
                        if '$t' in json_conf[element][i][item]:
                            json_conf[element][i][item] = json_conf[element][i][item]['$t']
    return json_conf


def prepare_ossecconf(json_conf):
    json_conf = "<root>"+json_conf+"</root>"
    return json_conf


def unify_ossecconf(json_conf):
    json_conf["root"]["ossec_config"] = merge_json_array(json_conf["root"]['ossec_config'])
    json_conf["root"]["ossec_config"]["global"] = merge_json_array(json_conf["root"]['ossec_config']["global"])
    json_conf["root"]["ossec_config"]["syscheck"] = merge_json_array(json_conf["root"]['ossec_config']["syscheck"])
    json_conf["root"]["ossec_config"]["rootcheck"] = merge_json_array(json_conf["root"]['ossec_config']["rootcheck"])
    json_conf = json_conf["root"]
    json_conf = process_ossecconf(json_conf['ossec_config'])
    return json_conf


class Configuration:
    def __init__(self, path='/var/ossec'):
        self.ossec_path = path
        self.path = "{0}/etc/ossec.conf".format(path)

    def get_ossec_conf(self, section=None, field=None):
        if import_problem is not None:
            raise WazuhException(1001, import_problem)
        else:
            with open(self.path, 'r') as f_ossec:
                read_conf = f_ossec.read()
                read_conf = prepare_ossecconf(read_conf)
                json_conf = xml_json.data(fromstring(read_conf))
                data = unify_ossecconf(json_conf)

        if section:
            data = data[section]
        if section and field:
            data = data[field] # data[section][field]

        return data

    def check(self):
        cmd = "{0}/bin/ossec-logtest".format(self.ossec_path)
        p = subprocess.Popen([cmd, "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, err) = p.communicate()

        lines = err.split(os.linesep)
        error_line = 0
        for l in lines:
            if "error" in l.lower():
                break
            else:
                error_line += 1

        if err:
            if "Error" in err:
                data = "{0}".format(lines[error_line:-1])
            else:
                data = "OK"
        else:
            raise WazuhException(1100)

        return data
