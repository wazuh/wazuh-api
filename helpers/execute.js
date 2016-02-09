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

var logger = require('../helpers/logger');
var errors = require('../helpers/errors');

/**
 * Exec command.
 * It returns (callback) always a JSON.
 * Input/Output
 *   Error: {'error': !=0, 'description': 'Error description'}
 *   OK: {'error': 0, 'response' = 'cmd output'}
 */
exports.exec = function(cmd, callback) {
    const exec = require('child_process').exec;

    var child = exec(cmd, function(error, stdout, stderr) {
        logger.logCommand(error, stdout, stderr);
        
        var json_result = "";

        if ( stdout ) {
            try {
                // String -> JSON
                json_result = JSON.parse(stdout);  // stdout could has: "error, response" or "error, description".
            } catch (e) {
                json_result = {"error": "501", "description": errors.description(501)};
            }
        }
        else{
            //if ( error != null || stderr != "")
            json_result = {"error": "500", "description": errors.description(500)};
        }
        
        callback(json_result);
    });
}
