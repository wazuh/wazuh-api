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
var bcrypt = require('bcrypt');

var secret = "f64f8bf42178a241ced799765949e00c"


function encrypt(password){
    return bcrypt.hashSync(password, 10);
}

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
    var inputData = [user.name];

    var sql = "SELECT name,password FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, function (err, result) {
        if (!err && bcrypt.compareSync(user.pass, result.password)) {
            exports.current_user_name = user.name;
            callback(false);
        } else {
            callback(true);
        }
    });
}

verify_user_enabled = function (username, callback) {
    var inputData = [username];
    var sql = "SELECT enabled FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, callback);
}

authenticate_user = function (user, callback) {
    verify_user(user, function (err, result) {
        if (err) {
            callback(false);
        } else {
            verify_user_enabled(user.name, function (err, result) {
                if (!err && result.enabled) {
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

    decode_token(token, function (err, token_decoded) {
        if (err) {
            callback(false);
        } else {
            verify_user_enabled(token_decoded.username, function (err, result) {
                if (!err && result.enabled) {
                    exports.current_user_name = token_decoded.username;
                    callback(true);
                } else {
                    callback(false);
                }

            });
        }
    });
}

exports.register_user = function (user_data, result) {
    exists_user(user_data.name, function (not_exists, data) {
        if (not_exists) {
            var inputData = [user_data.name, encrypt(user_data.password)];
            var sql = "INSERT INTO users (name, password, enabled) VALUES(?, ?, 1)";
            db_helper.db_run(sql, inputData, result);
        } else {
            result(true);
        }
    });
}

exists_user = function (user_name, callback) {
    var inputData = [user_name];
    var sql = "SELECT * FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, callback);
}

exports.get_user_id = function (user_name, callback) {
    var inputData = [user_name];
    var sql = "SELECT id FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, callback);
}

exports.update_user = function (user_data, callback) {
    exists_user(user_data.name, function (err, result) {
        if (!err) {
            var inputData = [user_data.enabled, user_data.name];
            var sql = "UPDATE users SET enabled = ? WHERE name = ?";
            db_helper.db_run(sql, inputData, callback);
        } else {
            callback(true);
        }
    });
}

exports.get_user = function (user_name, callback) {
    var inputData = [user_name];
    var sql = "SELECT * FROM users WHERE name = ?";
    db_helper.db_get(sql, inputData, callback);
}

exports.delete_user = function (user_name, callback) {
    exists_user(user_name, function (err, result) {
        if (!err) {
            var inputData = [user_name];
            var sql = "DELETE FROM users WHERE name=?";
            db_helper.db_run(sql, inputData, callback);
        } else {
            callback(true);
        }
    });
}

exports.get_all_users = function (callback) {
    var inputData = [];
    var sql = "SELECT name, enabled FROM users";
    db_helper.db_all(sql, inputData, callback);
}

exports.set_run_as_user = function (run_as_user) {
    if (run_as_user) {
        exports.current_user_name = run_as_user;
    }
}

exports.set_run_as_group = function (run_as_group) {
    if (run_as_group) {
        exports.run_as_group = run_as_group;
    }
}

exports.current_user_name = null; 
exports.authenticate_user = authenticate_user;
exports.get_token = get_token;
exports.authenticate_user_from_token = authenticate_user_from_token;
exports.exists_user = exists_user;