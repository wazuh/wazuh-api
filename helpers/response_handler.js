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

exports.send = function(res, json_r, status){

    if (typeof status == 'undefined')
        status = 200;

    // Validate json and status
    if (json_r != null && json_r.error != null && json_r.data != null && json_r.message != null && status >= 100 && status <= 600){

        // Calculate status
        if (json_r.error >= 1 && json_r.error <= 9)
            status = 500;

        // Pagination
        if ( Array.isArray(json_r.data) ){
            var new_data = [];
            var c = 0;
            for(var i = this.offset; i < json_r.data.length && c < this.limit; i++){
                new_data.push(json_r.data[i]);
                c++;
            }
            msg = json_r.msg;
            json_r = {'error': 0, 'data': new_data, 'message': msg};
        }
    }
    else{
        json_r = {"error": 3, "data": "", "message": errors.description(3)}; // Internal Error
        status = 500;
    }

    // Logging
    if (status == 200)
        logger.log("Response: {...OK...} HTTP Status: 200");
    else
        logger.log("Response: " + JSON.stringify(json_r) + " HTTP Status: " + status);

    // Send
    if (!res.headersSent){
        if (this.pretty)
            res.status(status).send(JSON.stringify( json_r, null, 3) + "\n");
        else
            res.status(status).json(json_r);
    }
}

exports.bad_request = function(internal_error, extra_msg, res){
    var msg = errors.description(internal_error);

    if (extra_msg)
        msg = msg + ". " + extra_msg;

    json_res = {'error': internal_error, 'data': "", 'message': msg};

    this.send(res, json_res, 400);
}
