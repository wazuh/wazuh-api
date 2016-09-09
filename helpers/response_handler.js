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
var fileSystem = require('fs');

exports.pretty = false;

exports.send = function(res, json_r, status){

    if (typeof status == 'undefined')
        status = 200;

    // Validate json and status
    if (json_r != null && json_r.error != null && (json_r.data != null || json_r.message != null) && status >= 100 && status <= 600){

        // Calculate status
        if (json_r.error >= 1 && json_r.error <= 9)
            status = 500;

    }
    else{
        json_r = {"error": 3, "message": errors.description(3)}; // Internal Error
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

    json_res = {'error': internal_error, 'message': msg};

    this.send(res, json_res, 400);
}

exports.send_file = function(rule_name, res){
    try {
        var filepath = "/var/ossec/rules/" +rule_name;
        var stat = fileSystem.statSync(filepath);

        res.writeHead(200, {
        'Content-Type': 'text/xml',
        'Content-Length': stat.size
        });

        var readStream = fileSystem.createReadStream(filepath);

        readStream.pipe(res)
    } catch (e) {
        if (e.code === 'ENOENT') {
            json_res = {'error': 700, 'message': errors.description(700) + ": " + filepath};
            this.send(res, json_res, 404);
        } else {
            json_res = {'error': 3, 'message': errors.description(3)};
            this.send(res, json_res, 500);
        }
    }

}
