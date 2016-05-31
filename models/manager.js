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

var execute = require('../helpers/execute');
var errors = require('../helpers/errors');
var config = require('../config.js');

var cmd_ossec_control = config.ossec_path + "/bin/ossec-control";

exports.status = function(callback){
    var args = ['-j', 'status'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.start = function(callback){
    var args = ['-j', 'start'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.stop = function(callback){
    var args = ['-j', 'stop'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.restart = function(callback){
    var args = ['-j', 'restart'];
    execute.exec(cmd_ossec_control, args, callback);
}

exports.config = function(filter, callback){
    var cmd = config.api_path + "/scripts/get_conf.py";
    execute.exec(cmd, [], function (json_output) {

        if (json_output.error == 0 && filter != null){

            if (filter.section){
                data_filtered = json_output.data[filter.section];
                if ( data_filtered != null && filter.field)
                    data_filtered = json_output.data[filter.section][filter.field];
            }

            if (data_filtered)
                r_data_filtered = {'error': 0, 'data': data_filtered, 'message': ""}
            else
                r_data_filtered = {'error': 0, 'data': "", 'message': ""}

            callback(r_data_filtered);
        }
        else{
            callback(json_output);
        }
    });
}

exports.testconfig = function(callback){
    var cmd = config.api_path + "/scripts/check_config.py";
    execute.exec(cmd, [], callback);
}

exports.stats = function(date, callback){
    var cmd = config.api_path + "/scripts/stats.py";
    var args = [];

    switch(date) {
        case "today":
            var moment = require('moment');
            date = moment().format('YYYYMMDD')
            args = ['-t', '-y', date.substring(0, 4), '-m', date.substring(4, 6), '-d', date.substring(6, 8)];
            break;
        case "hourly":
            args = ['-h'];
            break;
        case "weekly":
            args = ['-w'];
            break;
        default:
           args = ['-t', '-y', date.substring(0, 4), '-m', date.substring(4, 6), '-d', date.substring(6, 8)];
    }

    execute.exec(cmd, args, callback);
}

exports.info = function(callback){
    var fs = require('fs');

    fs.readFile('/etc/ossec-init.conf', function (err, data) {
        if (err)
            json_res = {'error': 1, 'data': '', 'message': errors.description(1)};
        else{
            lines = data.toString().split(/\r?\n/);
            var line_regex = /(^\w+)="(.+)"/;
            json_data = {};
            for (var i in lines) {
                var match = line_regex.exec(lines[i]);
                if (match && match[1] && match[2])
                    json_data[match[1].toLowerCase()] =match[2];
            }

            json_data["api_version"] = current_version;

            json_res = {'error': 0, 'data': json_data, 'message': ''};
        }
        callback(json_res);
    });
}
