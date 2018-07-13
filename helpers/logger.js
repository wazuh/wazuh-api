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
var fs = require('fs');

var tag = "WazuhAPI";
var f_log = config.log_path;
var foreground = false;
var LEVEL_DISABLED = 0;
var LEVEL_INFO = 1;
var LEVEL_WARNING = 2;
var LEVEL_ERROR = 3;
var LEVEL_DEBUG = 4;
var user = "";

var logger_level = LEVEL_INFO;
switch(config.logs) {
    case "INFO", "info":
        logger_level = LEVEL_INFO;
        break;
    case "WARNING", "warning":
        logger_level = LEVEL_WARNING;
        break;
    case "ERROR", "error":
        logger_level = LEVEL_ERROR;
        break;
    case "DEBUG", "debug":
        logger_level = LEVEL_DEBUG;
        break;
    case "DISABLED", "disabled":
        logger_level = LEVEL_DISABLED;
        break;
    default:
        logger_level = LEVEL_INFO;
}

exports.set_user = function(req_user) {
    user = req_user;
}

exports.set_foreground = function() {
    foreground = true;
}

function header(){
    return tag + " " + moment().format('YYYY-MM-DD HH:mm:ss') + " " + user + ": ";
}

function write_log(msg){
    if(foreground)
        console.log(msg);
    fs.appendFile(f_log, msg + "\n", {'mode': 0o640}, function(err) {
        if(err) {
            return console.error(err);
        }
    });
}

exports.log = function(message) {
    if(logger_level >= LEVEL_INFO)
        write_log(header() + message);
}

exports.warning = function(message) {
    if(logger_level >= LEVEL_WARNING)
        write_log(header() + message);
}

exports.error = function(message) {
    if(logger_level >= LEVEL_ERROR)
        write_log(header() + message);
}

exports.debug = function(message) {
    if(logger_level >= LEVEL_DEBUG)
        write_log(header() + message);
}
