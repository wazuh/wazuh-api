#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

try:
    from xmljson import gdata as xml_json
    from xml.etree.ElementTree import fromstring
    import json
except Exception as e:
        r_error = 70
        r_description = "Problem with import modules in command: {0}".format(e)
        
if __name__ == "__main__":
    ossec_path = "/var/ossec"
    ossec_conf = "{0}/etc/ossec.conf".format(ossec_path)
    r_error = 0
    r_description = ""
    r_response = ""
    
    try:
        r_error = 0
        
        with open(ossec_conf) as f_ossec:
            r_response = xml_json.data(fromstring(f_ossec.read()))

    except Exception as e:
        r_error = 71
        r_description = "Problem running command: {0}".format(e)

    # Response
    response = {'error': r_error}
    if r_error == 0:
        response['response'] = r_response
    else:
        response['description'] = r_description
    
    print(json.dumps(response))
