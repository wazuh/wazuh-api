/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

var execute = require('../helpers/execute');
var errors = require('../helpers/errors');
var jsutils = require('../helpers/js_utils');

exports.status = function(callback){
    var cmd = "/var/ossec/bin/ossec-control -j status"
    result = execute.exec(cmd, callback);
}

exports.start = function(callback){
    var cmd = "/var/ossec/bin/ossec-control -j start"
    result = execute.exec(cmd, callback);
}

exports.stop = function(callback){
    var cmd = "/var/ossec/bin/ossec-control -j stop"
    result = execute.exec(cmd, callback);
}

exports.settings = function(filter, callback){
    var cmd = "python /home/repos/wazuh-API/scripts/get_conf.py"
    result = execute.exec(cmd, function (data) {

        if (data.error == 0 && !jsutils.isEmptyObject(filter)){
            data_filtered = data.response.ossec_config[filter.section];
            
            if (data_filtered)
                r_data_filtered = {'error': 0, 'response': data_filtered};
            else{
                r_data_filtered = {'error': 0, 'response': null};
            }

            callback(r_data_filtered);
        }
        else{
            callback(data);
        }
    });
}
