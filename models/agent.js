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
var cmd_syscheck_control = config.ossec_path + "/bin/syscheck_control";
var cmd_rootcheck_control = config.ossec_path + "/bin/rootcheck_control";


/********************************************/
/* Agent
/********************************************/

exports.all = function(callback){
    var args = ['-j', '-l'];
    execute.exec(cmd_agent_control, args, callback);
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
    var cmd = "/var/ossec/api/scripts/api_getkey_agent.sh";
    var args = [id];
    execute.exec(cmd, args, callback);
}

exports.add = function(name, callback){
    var cmd = "/var/ossec/api/scripts/api_add_agent.sh";
    var args = [name];
    execute.exec(cmd, args, callback);
}

exports.remove = function(id, callback){
    var cmd = "/var/ossec/api/scripts/remove_agent.py";
    var args = ['-i', id];
    execute.exec(cmd, args, callback);
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
    var cmd = [];
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
