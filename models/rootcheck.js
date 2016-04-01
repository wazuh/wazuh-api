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
var config = require('../config.js');
var agent = require('./agent');
var syscheck = require('./syscheck');

var cmd_rootcheck_control = config.ossec_path + "/bin/rootcheck_control";


/********************************************/
/* Rootcheck
/********************************************/
exports.run = function(id, callback){
    syscheck.run(id, callback)
}

/**
 * Clear rootcheck database for all/the agent.
 * If id is ALL, clear the database for all agent.
 */
exports.clear = function(id, callback){
    if (id == "ALL")
        args = ['-j', '-u', 'all'];
    else
        args = ['-j', '-u', id];
    execute.exec(cmd_rootcheck_control, args, callback);
}

exports.print_db = function(id, callback){
    var args = ['-j', '-i', id];
    execute.exec(cmd_rootcheck_control, args, callback);
}

exports.last_scan = function(id, callback){
    agent.info(id, function (json_output) {
        if (json_output.error == 0){
            data_time = {'rootcheckTime': json_output.data.rootcheckTime, 'rootcheckEndTime': json_output.data.rootcheckEndTime};
            callback({'error': 0, 'data': data_time, 'message': ""});
        }
        else
            callback(json_output)
    });
}
