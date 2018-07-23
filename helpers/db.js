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
var fs = require('fs');
const dbPath = path.resolve(__dirname, '../api.db');
var first_time = !(fs.existsSync(dbPath));

var db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE);

if (first_time){
    exports.db = db.serialize(function () {
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, password TEXT NOT NULL, enabled INTEGER DEFAULT 1, reserved INTEGER DEFAULT 0)");
        db.run("INSERT INTO users (name, password, enabled, reserved) VALUES('wazuh-app', '', 1, 1)");
        db.run("INSERT INTO users (name, password, enabled, reserved) VALUES('wazuh', '', 1, 1)");
        db.run("INSERT INTO users (name, password, enabled, reserved) VALUES('foo', '', 1, 0)");
    });
}

function db_get(sql, inputData, callback) {
    db.get(sql, inputData, function (err, row) {
        if (!row || err) {
            var reason = "";
            if (err)
                msg = "Error in DB query. Reason: " + err + ". Query: " + sql + " (" + inputData + ").";
            else if (!row)
                msg = "No result in DB query. Query: " + sql + " (" + inputData + ").";
            logger.debug(msg);
            callback(true, err);
        } else {
            callback(false, row);
        }
    });
}

function db_run(sql, inputData, callback) {
    db.run(sql, inputData, function (err) {
        if (err) {
            var reason = "";
            if (err)
                reason = "Reason: " + err;
            logger.debug("Error in DB query. " + reason);
            callback(true, err);
        } else {
            callback(false);
        }
    });
}

function db_all(sql, inputData, callback) {
    db.all(sql, inputData, function (err, rows) {
        if (!rows || err) {
            var reason = "";
            if (err)
                reason = "Reason: " + err;
            else if (!rows)
                reason = "Reason: No result.";
            logger.debug("Error in DB query. " + reason);
            callback(true, err);
        } else {
            callback(false, rows);
        }
    });
}

exports.close = function () {
    db.close(function(err){
        if (err)
            logger.debug(err.message);
    });
}

exports.db_get = db_get;
exports.db_run = db_run;
exports.db_all = db_all;