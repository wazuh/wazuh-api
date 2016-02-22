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
