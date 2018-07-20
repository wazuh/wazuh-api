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
const dbPath = path.resolve(__dirname, '../api.db')
var db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE);

exports.db = db.serialize(function () {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT NOT NULL, enabled INTEGER NOT NULL)");
    db.run("INSERT INTO users (name, password, enabled) VALUES('foo', '', 1)");
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


exports.db_get = db_get;
exports.db_run = db_run;
exports.db_all = db_all;