#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

r_error = 0
r_message = ""

import json
import xml.etree.ElementTree
    
try:
    from xmljson import gdata as xml_json
    from xml.etree.ElementTree import fromstring
except Exception as e:
        r_error = 50
        r_message = "Problem with import modules in command: {0}".format(e)
   
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

if __name__ == "__main__":
    ossec_path = "/var/ossec"
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    r_data = ""
    
    if r_error == 0:
        try:
            r_error = 0
            with open(ossec_conf, 'r') as f_ossec:
                read_conf = f_ossec.read()
                read_conf = prepare_ossecconf(read_conf)
                json_conf = xml_json.data(fromstring(read_conf))
                r_data = unify_ossecconf(json_conf)
        except Exception as e:
            r_error = 51
            r_message = "Problem running command: {0}".format(e)

    # Response
    response = {'error': r_error}
    if r_error == 0:
        response['data'] = r_data
    else:
        response['message'] = r_message
    
    print(json.dumps(response))

