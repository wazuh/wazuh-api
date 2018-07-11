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
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, password TEXT NOT NULL)");
    db.run("INSERT INTO users (name, password) VALUES('foo', 'bar')");
});


exports.get_user_id = function (user_name, callback) {
    db.get("SELECT id FROM users WHERE name = ?", user_name, function (err, row) {
        if (!row) {
            callback(err);
        } else {
            callback(row);
        }
    });
}