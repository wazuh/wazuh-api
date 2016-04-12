#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

r_error = 0
r_message = ""

import json

try:
    from xmljson import gdata as xml_json
    from xml.etree.ElementTree import fromstring
except Exception as e:
        r_error = 50
        r_message = "Problem with import modules in command: {0}".format(e)

def remove_json_array(json_array):
    new_json = {}
    for element in json_array:
        for item in element:
            new_json[item] = element[item]

    return new_json

def process_ossecconf(json_conf):
    new_json = {}
    
    for element in json_conf:
        if element == "global":
            new_json["global"] = remove_json_array(json_conf['global'])
        else:   
            new_json[element] = json_conf[element]
    return new_json

if __name__ == "__main__":
    ossec_path = "/var/ossec"
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    r_data = ""
    
    if r_error == 0:
        try:
            r_error = 0
            
            with open(ossec_conf) as f_ossec:
                read_conf = f_ossec.read()
                read_conf_tmp = ""
                for c in read_conf.split("</ossec_config>\n\n<ossec_config>"):
                    read_conf_tmp += c
                if (read_conf_tmp != ""):
                    read_conf = read_conf_tmp
                json_conf = xml_json.data(fromstring(read_conf))

        
            r_data = process_ossecconf(json_conf['ossec_config'])

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
