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

exports.settings = function(callback){
    var cmd = "python /home/repos/wazuh-API/scripts/get_conf.py"
    result = execute.exec(cmd, callback);
}
