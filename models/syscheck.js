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
var agent = require('./agent.js');

var cmd_agent_control = config.ossec_path + "/bin/agent_control";
var cmd_syscheck_control = config.ossec_path + "/bin/syscheck_control";

/********************************************/
/* Syscheck
/********************************************/

/**
 * Run syscheck / rootcheck in an agent.
 * If id is ALL, run syscheck / rootcheck for all agents.
 */
exports.run = function(id, callback){
    var args = [];
    if (id == "ALL")
        args = ['-j', '-r', '-a'];
    else
        args = ['-j', '-r', '-u', id];
    execute.exec(cmd_agent_control, args, callback);
}

/**
 * Clear syscheck database for all/the agent.
 * If id is ALL, clear the database for all agent.
 */
exports.clear = function(id, callback){
    var args = [];
    if (id == "ALL")
        args = ['-j', '-u', 'all'];
    else
        args = ['-j', '-u', id];
    execute.exec(cmd_syscheck_control, args, callback);
}

exports.files_changed = function(id, filename, callback){
    var args = ['-j', '-i', id];
    if (filename != null)
        args = ['-j', '-i', id, '-f', filename];
    else
        args = ['-j', '-i', id];
    
    execute.exec(cmd_syscheck_control, args, callback);
}

exports.last_scan = function(id, callback){
    agent.info(id, function (json_output) {
        if (json_output.error == 0){
            data_time = {'syscheckTime': json_output.data.syscheckTime, 'syscheckEndTime': json_output.data.syscheckEndTime};
            callback({'error': 0, 'data': data_time, 'message': ""});
        }
        else
            callback(json_output)
    });
}
