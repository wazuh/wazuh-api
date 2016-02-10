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

var cmd_ossec_control = "/var/ossec/bin/ossec-control";

exports.status = function(callback){
    var args = ['-j', 'status'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.start = function(callback){
    var args = ['-j', 'start'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.stop = function(callback){
    var args = ['-j', 'stop'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.settings = function(filter, callback){
    var cmd = "/home/repos/wazuh-API/scripts/get_conf.py";
    execute.exec(cmd, [], function (data) {

        if (data.error == 0 && !jsutils.isEmptyObject(filter)){
            
            if(filter.section && filter.field)
                data_filtered = data.response[filter.section][filter.field];
            else
                data_filtered = data.response[filter.section];
            
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
