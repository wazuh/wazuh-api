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

exports.all = function(callback){
    var cmd = "/var/ossec/bin/agent_control -lj";
    result = execute.exec(cmd, callback);
}

exports.get_key = function(id, callback){
    var cmd = "sh /var/ossec/api/scripts/api_getkey_agent.sh " + id;
    result = execute.exec(cmd, callback);
}

exports.info = function(id, callback){
    var cmd = "/var/ossec/bin/agent_control -j -e -i " + id;
    result = execute.exec(cmd, callback);
}

exports.add = function(name, callback){
    var cmd = "sh /var/ossec/api/scripts/api_add_agent.sh " + name;
    result = execute.exec(cmd, callback);
}

exports.restart = function(id, callback){
    var cmd = "/var/ossec/bin/agent_control -j -R " + id;
    result = execute.exec(cmd, callback);
}

/**
 * Run syscheck / rootcheck in an agent.
 * If id is ALL, run syscheck / rootcheck for all agents.
 */
exports.run_syscheck = function(id, callback){
    var cmd = "";
    if (id == "ALL"){
        cmd = "/var/ossec/bin/agent_control -j -r -a";
    }
    else{
        cmd = "/var/ossec/bin/agent_control -j -r -u " + id;
    }

    result = execute.exec(cmd, callback);
}

exports.run_rootcheck = function(id, callback){
    this.run_syscheck(id, callback)
}

exports.remove = function(id, callback){
    var cmd = "python /var/ossec/api/scripts/remove_agent.py -i " + id;
    result = execute.exec(cmd, callback);
}
