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


/********************************************/
/* Agent
/********************************************/

exports.all = function(callback){
    var cmd = "/var/ossec/bin/agent_control -lj";
    result = execute.exec(cmd, callback);
}

exports.info = function(id, callback){
    var cmd = "/var/ossec/bin/agent_control -j -e -i " + id;
    result = execute.exec(cmd, callback);
}

exports.restart = function(id, callback){
    var cmd = "/var/ossec/bin/agent_control -j -R " + id;
    result = execute.exec(cmd, callback);
}

exports.get_key = function(id, callback){
    var cmd = "sh /var/ossec/api/scripts/api_getkey_agent.sh " + id;
    result = execute.exec(cmd, callback);
}

exports.add = function(name, callback){
    var cmd = "sh /var/ossec/api/scripts/api_add_agent.sh " + name;
    result = execute.exec(cmd, callback);
}

exports.remove = function(id, callback){
    var cmd = "python /var/ossec/api/scripts/remove_agent.py -i " + id;
    result = execute.exec(cmd, callback);
}


/********************************************/
/* Agent - Syscheck
/********************************************/

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

/**
 * Clear syscheck database for all/the agent.
 * If id is ALL, clear the database for all agent.
 */
exports.clear_syscheck = function(id, callback){
    var cmd = "";
    if (id == "ALL"){
        cmd = "/var/ossec/bin/syscheck_control -j -u all";
    }
    else{
        cmd = "/var/ossec/bin/syscheck_control -j -u " + id;
    }

    result = execute.exec(cmd, callback);
}

exports.syscheck_modified_files = function(id, callback){
    var cmd = "/var/ossec/bin/syscheck_control -j -i " + id;
    result = execute.exec(cmd, callback);
}

exports.syscheck_modified_file = function(id, filename, callback){
    var cmd = "/var/ossec/bin/syscheck_control -j -i " + id + " -f " + filename;
    result = execute.exec(cmd, callback);
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
    var cmd = "";
    if (id == "ALL"){
        cmd = "/var/ossec/bin/rootcheck_control -j -u all";
    }
    else{
        cmd = "/var/ossec/bin/rootcheck_control -j -u " + id;
    }

    result = execute.exec(cmd, callback);
}

exports.print_rootcheck_db = function(id, callback){
    var cmd = "/var/ossec/bin/rootcheck_control -j -i " + id;
    result = execute.exec(cmd, callback);
}
