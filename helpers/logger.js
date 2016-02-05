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

// ToDo: Move debug var to app.js ?
var debug = true;

function header(){
    return tag + " " + moment().format('YYYY-MM-DD HH:mm:ss') + ": ";
}

exports.logCommand = function(error, stdout, stderr) {
    var head = header() + "CMD -";

    if(error != null && error > 1)
        console.error(head + " error:" + error);

    if(stderr != "")
        console.error(head + " stderr:" + stderr);

    if(debug)
        console.log(head + " stdout:" + stdout);
}

exports.log = function(message) {
    if(debug)
        console.log(header() + message);
}

exports.debug = debug;
