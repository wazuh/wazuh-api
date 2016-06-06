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
var config = require('../config.js');

var cmd_ossec_control = config.ossec_path + "/bin/ossec-control";

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

exports.restart = function(callback){
    var args = ['-j', 'restart'];
    execute.exec(cmd_ossec_control, args, callback);
}
