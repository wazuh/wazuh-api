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

var moment = require('moment');

var tag = "WazuhAPI";
var LEVEL_INFO = 1;
var LEVEL_WARNING = 2;
var LEVEL_ERROR = 3;
var LEVEL_DEBUG = 4;

// ToDo: Move debug var to app.js ?
var logger_level = LEVEL_DEBUG;

function header(){
    return tag + " " + moment().format('YYYY-MM-DD HH:mm:ss') + ": ";
}

exports.logCommand = function(cmd, error, stdout, stderr) {
    var head = header() + "CMD -";

    if(logger_level >= LEVEL_DEBUG)
        console.log(head + cmd);

    if (logger_level >= LEVEL_ERROR){
        if(error != null)
            console.error(head + " error:" + error);

        if(stderr != "")
            console.error(head + " stderr:" + stderr);
    }
    if(logger_level >= LEVEL_DEBUG)
        console.log(head + " stdout:" + stdout);
}

exports.log = function(message) {
    if(logger_level >= LEVEL_INFO)
        console.log(header() + message);
}
