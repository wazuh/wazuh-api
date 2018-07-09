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

var jwt = require('jsonwebtoken');

var secret = "f64f8bf42178a241ced799765949e00c"
var expire_time = 86400 // expires in 24 hours

exports.get_token = function (user_id){
    return token = jwt.sign({ id: user_id }, secret, {
        expiresIn: expire_time
    });
}

exports.verify_token = function (token) {
    var result = false
    jwt.verify(token, secret, function (err, decoded) {
        if (!err) {
            result = true; 
        }
    });
    return result;
}