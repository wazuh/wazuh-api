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
var db_helper = require('../helpers/db');

var secret = "f64f8bf42178a241ced799765949e00c"

exports.current_user_name = null

exports.get_token = function (user_name){
    return token = jwt.sign({ username: user_name }, secret, {
        expiresIn: config.token_expiration_time
    });
}

exports.decode_token = function (token, callback) {
    jwt.verify(token, secret, function (err, decoded) {
        if (!err && decoded) {
            callback(false, decoded);
        } else { 
            callback(true, null);
        }
        
    });
}

exports.verify_user = function (user, callback) {
    db_helper.db.get("SELECT name FROM users WHERE name = ? AND password = ?", user.name, user.pass, function (err, row) {
        if (!row || err) {
            callback(false);
        } else {
            callback(true);
        }
    });
}