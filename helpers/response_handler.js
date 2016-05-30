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

exports.pretty = false;
exports.offset = 0;
exports.limit = 100;

exports.send = function(res, json, status){
    if (this.pretty){
        try {
            res.status(status).send(JSON.stringify( json, null, 3) + "\n");
        } catch (e) {
            json_result = {"error": 3, "data": "", "message": errors.description(3)}; // OUTPUT Not JSON
        }
    }
    else
        res.status(status).json(json);
}

/**
 * cmd
 * Use this handler for *execute.exec*.
 *
 * When error is 01 or 02 -> status is 500
 */
exports.cmd = function(json_cmd_output, res){
    var status = 200;
    var json_res = json_cmd_output;

    if (json_cmd_output.error != 0){
        if (json_cmd_output.error == "01" || json_cmd_output.error == "02")
            status = 500;
        logger.log("Response: " + JSON.stringify(json_cmd_output) + " HTTP Status: " + status);
    }
    else{
        new_data = [];
        if ( Array.isArray(json_cmd_output.data) ){
            var c = 0;
            for(var i = this.offset; i < json_cmd_output.data.length && c < this.limit; i++){
                new_data.push(json_cmd_output.data[i]);
                c++;
            }
            json_res = {'error': 0, 'data': new_data, 'message': json_cmd_output.msg};
        }

        logger.log("Response: {...} HTTP Status: 200");
    }

    this.send(res, json_res, status);
}

exports.bad_request = function(internal_error, extra_msg, res){
    var msg = errors.description(internal_error);

    if (extra_msg)
        msg = msg + ". " + extra_msg;

    json_res = {'error': internal_error, 'data': "", 'message': msg};

    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 400");

    this.send(res, json_res, 400);
}
