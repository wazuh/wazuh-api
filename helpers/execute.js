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
 * Input
 *   Error: {'error': !=0, 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output'}
 * Output
 *   Error: {'error': !=0, 'data'= "", 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output', 'message': ""}
 */
exports.exec = function(cmd, args, callback) {
    const child_process  = require('child_process');

    child_process.execFile(cmd, args, function(error, stdout, stderr) {
        if (args != null)
            full_cmd = cmd + " " + args.toString();
        else
            full_cmd = cmd;
        logger.logCommand(full_cmd, error, stdout, stderr);
        
        var json_result = {};

        if ( stdout ) {
            try {
                var json_cmd = JSON.parse(stdout); // String -> JSON
                
                if ( json_cmd.hasOwnProperty('error') ){
                
                    json_result.error = json_cmd.error;
                    
                    if ( json_cmd.hasOwnProperty('data') )
                        json_result.data = json_cmd.data;
                    else
                        json_result.data = "";

                    if ( json_cmd.hasOwnProperty('message') )
                        json_result.message = json_cmd.message;
                    else
                        json_result.message = "";
                }
                else
                    json_result = {"error": 1, "data": "", "message": errors.description(1)}; // Internal Error
                
            } catch (e) {
                json_result = {"error": 2, "data": "", "message": errors.description(2)}; // OUTPUT Not JSON
            }
        }
        else{
            //if ( error != null || stderr != "")
            json_result = {"error": 1, "data": "", "message": errors.description(1)}; // Internal Error
        }
        
        callback(json_result);
    });
}
