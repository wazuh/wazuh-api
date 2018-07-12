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


get_token = function (user_name){
    return token = jwt.sign({ username: user_name }, secret, {
        expiresIn: config.token_expiration_time
    });
}

decode_token = function (token, callback) {
    jwt.verify(token, secret, function (err, decoded) {
        if (!err && decoded) {
            callback(false, decoded);
        } else {
            var reason = err.message;
            if (err.name == "TokenExpiredError"){
                var reason = err.message + " at " + err.expiredAt;
            }
            logger.debug("Failed to authenticate token. Reason: " + reason);
            callback(true);
        }
        
    });
}

verify_user = function (user, callback) {
    var inputData = [user.name, user.pass];
    var sql = "SELECT name FROM users WHERE name = ? AND password = ?";
    db_helper.db_get(sql, inputData, callback);
}

verify_user_enabled = function (username, callback) {
    var inputData = [username];
    var sql = "SELECT enabled FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, callback);
}

authenticate_user = function (user, callback) {
    verify_user(user, function (result) {
        if (!result) {
            callback(false);
        } else {
            verify_user_enabled(user.name, function (result) {
                if (result.enabled) {
                    exports.current_user_name = user.name;
                    callback(true);
                } else {
                    callback(false);
                }

            });
        }
    });
}

authenticate_user_from_token = function (token, callback) {

    decode_token(token, function (error, token_decoded) {
        if (error) {
            callback(false);
        } else {
            verify_user_enabled(token_decoded.username, function (result) {
                if (result.enabled) {
                    exports.current_user_name = token_decoded.username;
                    callback(true);
                } else {
                    callback(false);
                }

            });
        }
    });
}

exports.current_user_name = null; 
exports.authenticate_user = authenticate_user;
exports.get_token = get_token;
exports.authenticate_user_from_token = authenticate_user_from_token;