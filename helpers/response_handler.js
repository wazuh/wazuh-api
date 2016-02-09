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

var errors = require('../helpers/errors');
var logger = require('../helpers/logger');

/**
 * cmd
 * Use this handler for *execute.exec*.
 *
 * json_cmd_output:
 *   Error: {'error': !=0, 'description': 'Error description'}
 *   OK: {'error': 0, 'response' = 'cmd output'}
 * output:
 *   Error: {'error': !=0, 'response': null, 'message': 'Error description'}
 *   OK: {'error': 0, 'response' = 'cmd output', 'message': null}
 */
exports.cmd = function(json_cmd_output, res){
    var status = 200;
    var json_res;

    
    if (json_cmd_output.error != 0){
        status = 500;
        json_res = {'error': json_cmd_output.error, 'response': null, 'message': json_cmd_output.description};
    }
    else{
        status = 200;
        json_res = {'error': '0', 'response': json_cmd_output.response, 'message': null};
    }
    
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: " + status);
    
    res.status(status).json(json_res);
}

exports.bad_request = function(internal_error, extra_msg, res){
    var msg = errors.description(internal_error);
    
    if (extra_msg)
        msg = msg + ": " + extra_msg;
    
    json_res = {'error': internal_error, 'response': null, 'message': msg};
    
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 400");
    
    res.status(400).json(json_res);
}
