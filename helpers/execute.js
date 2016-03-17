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
exports.exec = function(cmd, args, callback) {
    const child_process  = require('child_process');

    child_process.execFile(cmd, args, function(error, stdout, stderr) {
        if (args != null)
            full_cmd = cmd + " " + args.toString();
        else
            full_cmd = cmd;
        logger.logCommand(full_cmd, error, stdout, stderr);
        
        var json_result = "";

        if ( stdout ) {
            try {
                // String -> JSON
                json_result = JSON.parse(stdout);  // stdout could have: "error, response" or "error, description".
            } catch (e) {
                json_result = {"error": "02", "description": errors.description("02")};
            }
        }
        else{
            //if ( error != null || stderr != "")
            json_result = {"error": "01", "description": errors.description("01")};
        }
        
        callback(json_result);
    });
}
