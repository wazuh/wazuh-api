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

var sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.resolve(config.ossec_path + '/api', 'api.db')

var db = new sqlite3.Database('api.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE);

exports.db = db.serialize(function () {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT NOT NULL, enabled INTEGER NOT NULL)");
    db.run("INSERT INTO users (name, password, enabled) VALUES('foo', 'bar', 1)");
});

function db_get(sql, inputData, callback) {
    db.get(sql, inputData, function (err, row) {
        if (!row || err) {
            var reason = "";
            if (err)
                reason = "Reason: " + err;
            else if (!row)
                reason = "Reason: No result.";
            logger.debug("Error in DB query. " + reason);
            callback(err);
        } else {
            callback(row);
        }
    });
}

function db_run(sql, inputData, callback) {
    db.run(sql, inputData, function (err) {
        if (!err)
            callback(true);
        else
            callback(err);
    });
}


exports.get_user_id = function (user_name, callback) {
    var inputData = [user_name];
    var sql = "SELECT id FROM users WHERE name = ?";
    db_get(sql, inputData, callback);
}


exports.update_user = function (user_data, callback) {
    var inputData = [user_data.enabled, user_data.name];
    var sql = "UPDATE users SET enabled = ? WHERE name = ?";
    db_run(sql, inputData, callback);
}


exports.get_user = function (user_name, callback) {
    var inputData = [user_name];
    var sql = "SELECT * FROM users WHERE name = ?";
    db_get(sql, inputData, callback);
}

exports.db_get = db_get;