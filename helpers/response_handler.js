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
    
    console.log(json_cmd_output)
    json_data = JSON.parse(json_cmd_output);
        
    if (json_data.error != 0){
        status = 500;
        json_res = {'error': json_data.error, 'response': null, 'message': json_data.description};
    }
    else{
        status = 200;
        json_res = {'error': '0', 'response': json_data.response, 'message': null};
    }

    res.status(status).json(json_res);
}

exports.bad_request = function(internal_error, extra_msg, res){
    var msg = errors.description(internal_error);
    
    if (extra_msg)
        msg = msg + ": " + extra_msg;
    
    res.status(400).json({'error': internal_error, 'response': null, 'message': msg});
}
