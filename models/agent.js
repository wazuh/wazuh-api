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

var cmd_agent_control = config.ossec_path + "/bin/agent_control";
var cmd_manage_agents = config.ossec_path + "/bin/manage_agents";
var cmd_syscheck_control = config.ossec_path + "/bin/syscheck_control";
var cmd_rootcheck_control = config.ossec_path + "/bin/rootcheck_control";


/********************************************/
/* Agent
/********************************************/

exports.all = function(filter, callback){
    var args = ['-j', '-l'];
    execute.exec(cmd_agent_control, args, function (data) {

        if (data.error == 0 && filter != null){
            
            var data_filtered = [];
            
            for(var i=0;i<data.response.length;i++){
                var agent = data.response[i];
                if (agent.status.toLowerCase() == filter.status.toLowerCase())
                    data_filtered.push(agent)
            }
            
            r_data_filtered = {'error': 0, 'response': data_filtered};
            
            callback(r_data_filtered);
        }
        else{
            callback(data);
        }
    });
}

exports.info = function(id, callback){
    var args = ['-j', '-e', '-i', id];
    execute.exec(cmd_agent_control, args, callback);
}

exports.restart = function(id, callback){
    var args = ['-j', '-R', id];
    execute.exec(cmd_agent_control, args, callback);
}

exports.get_key = function(id, callback){
    var args = ['-j', '-e', id];
    execute.exec(cmd_manage_agents, args, callback);
}

exports.add = function(name, ip, callback){
    var args;
    
    if (ip.toLowerCase() == "any")
        args = ['-j', '-a', 'any', '-n', name];
    else{
        // ToDo: Checks
        /*
        ** IP already on OSSEC List?
        **  Yes: Is the agent active?
        **      Yes: Do nothing, generate alert.
        **      No: Comment(remove)  old agent and add the new one
        **  No: Add agent
        */
        args = ['-j', '-a', ip, '-n', name];
    }
    
    execute.exec(cmd_manage_agents, args, callback);
}

exports.remove = function(id, callback){
    var args = ['-j', '-r', id];
    execute.exec(cmd_manage_agents, args, callback);
}


/********************************************/
/* Agent - Syscheck
/********************************************/

/**
 * Run syscheck / rootcheck in an agent.
 * If id is ALL, run syscheck / rootcheck for all agents.
 */
exports.run_syscheck = function(id, callback){
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
exports.clear_syscheck = function(id, callback){
    var args = [];
    if (id == "ALL")
        args = ['-j', '-u', 'all'];
    else
        args = ['-j', '-u', id];
    execute.exec(cmd_syscheck_control, args, callback);
}

exports.syscheck_modified_files = function(id, callback){
    var args = ['-j', '-i', id];
    execute.exec(cmd_syscheck_control, args, callback);
}

exports.syscheck_modified_file = function(id, filename, callback){
    var args = ['-j', '-i', id, '-f', filename];
    execute.exec(cmd_syscheck_control, args, callback);
}

exports.syscheck_last_scan = function(id, callback){
    this.info(id, function (data) {
        if (data.error == 0){
            data_time = {'syscheckTime': data.response.syscheckTime, 'syscheckEndTime': data.response.syscheckEndTime};
            callback({'error': 0, 'response': data_time});
        }
        else
            callback(data)
    });
}

/********************************************/
/* Agent - Rootcheck
/********************************************/
exports.run_rootcheck = function(id, callback){
    this.run_syscheck(id, callback)
}

/**
 * Clear rootcheck database for all/the agent.
 * If id is ALL, clear the database for all agent.
 */
exports.clear_rootcheck = function(id, callback){
    if (id == "ALL")
        args = ['-j', '-u', 'all'];
    else
        args = ['-j', '-u', id];
    execute.exec(cmd_rootcheck_control, args, callback);
}

exports.print_rootcheck_db = function(id, callback){
    var args = ['-j', '-i', id];
    execute.exec(cmd_rootcheck_control, args, callback);
}

exports.rootcheck_last_scan = function(id, callback){
    this.info(id, function (data) {
        if (data.error == 0){
            data_time = {'rootcheckTime': data.response.rootcheckTime, 'rootcheckEndTime': data.response.rootcheckEndTime};
            callback({'error': 0, 'response': data_time});
        }
        else
            callback(data)
    });
}
