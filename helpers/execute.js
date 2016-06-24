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
var timeout = 30; // seconds

exports.query_offset = 0;
exports.query_limit = 0;
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

    // Add pagination
    args.push("-p");
    args.push(this.query_offset + "," + this.query_limit);
    logger.debug("CMD - Pagination: " + this.query_offset + " " + this.query_limit);

    // log
    var full_cmd = "CMD - Command: " + cmd + " " + args.join(' ')
    logger.debug(full_cmd);

    const command = child_process.spawn(cmd, args);

    var output = [];
    var error = false;

    setTimeout(function(){
        logger.debug("Sending SIGTERM to " + full_cmd)
        command.kill('SIGTERM');
    }, timeout*1000);

    command.stdout.on('data', (chunk) => {
        output.push(chunk)
        //console.log("Chunk: " + Buffer.byteLength(chunk, 'utf8') + " bytes");
    });

    command.on('error', function(err) {
        logger.error("CMD - Error executing command: " + err);
        error = true;
        callback({"error": 1, "data": "", "message": errors.description(1)});  // Error executing internal command
    });

    command.on('close', (code) => {
        logger.debug("CMD - Exit code: " + code);
        if (!error){
            var json_result = {};

            if (code != 0){  // Exit code must be 0
              json_result = {"error": 1, "data": "", "message": errors.description(1) + ". Exit code: " + code};  // Error executing internal command
            }
            else{
                var json_cmd = {}
                // Check JSON
                var stdout = output.join('');
                logger.debug("CMD - STDOUT:\n---\n" + stdout + "\n---");
                logger.debug("CMD - STDOUT: " + Buffer.byteLength(stdout, 'utf8') + " bytes");
                json_cmd = tryParseJSON(stdout)

                if (!json_cmd){
                    logger.debug("CMD - STDOUT NOT JSON");
                    json_result = {"error": 2, "data": "", "message": errors.description(2)}; // OUTPUT Not JSON
                }
                else{
                    // Check JSON content
                    if ( json_cmd.hasOwnProperty('error') && ( json_cmd.hasOwnProperty('message') || json_cmd.hasOwnProperty('data') ) ){

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
                    else{
                        json_result = {"error": 1, "data": "", "message": errors.description(1) + ". Wrong keys"}; // JSON Wrong keys
                        logger.error("CMD - Wrong keys: " + Object.keys(json_cmd));
                    }
                }
            }
            callback(json_result);
        }
    });

}

function tryParseJSON (jsonString){
    try {
        var o = JSON.parse(jsonString);

        if (o && typeof o === "object" && o !== null) {
            return o;
        }
    }
    catch (e) { }

    return false;
};
