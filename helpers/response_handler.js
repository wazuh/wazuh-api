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
 * When error is 01 or 02 -> status is 500
 */
exports.cmd = function(json_cmd_output, res){
    var status = 200;

    if (json_cmd_output.error != 0){
        if (json_cmd_output.error == "01" || json_cmd_output.error == "02")
            status = 500;
        logger.log("Response: " + JSON.stringify(json_cmd_output) + " HTTP Status: " + status);
    }
    else
        logger.log("Response: {...} HTTP Status: 200");
    
    res.status(status).json(json_cmd_output);
}
exports.bad_generic_request = function(message, error, res){
    var status = 200;
    json_res = {'error': error, 'data': "", 'message': message};
    res.status(status).json(json_res);
}
exports.bad_request = function(internal_error, extra_msg, res){
    var msg = errors.description(internal_error);
    
    if (extra_msg)
        msg = msg + ". " + extra_msg;
    
    json_res = {'error': internal_error, 'data': "", 'message': msg};
    
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 400");
    
    res.status(400).json(json_res);
}
