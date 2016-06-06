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

var express = require('express');
var router = express.Router();
var manager = require('../models/manager');
var res_h = require('../helpers/response_handler');
var req_h = require('../helpers/request_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');
var config = require('../config.js');
var execute = require('../helpers/execute');
var wazuh_control = config.api_path + "/models/wazuh-control.py";
/**
 *
 * PUT /manager/start - Start manager
 * PUT /manager/stop - Stop manager
 * PUT /manager/restart - Restart manager
 * GET /manager/status - Get manager status
 * GET /manager/info - Get manager info
 * GET /manager/configuration - Get manager configuration
 *   GET /manager/configuration?section=rules - Get rules in ossec.conf
 * GET /manager/configuration/test - Test configuration
 * GET /manager/stats - Stats Today
 *   GET /manager/stats?date=YYYYMMDD - Stats YYYYMMDD
 * GET /manager/stats/hourly - Stats hourly averages.
 * GET /manager/stats/weekly - Stats weekly-hourly averages
 *
**/


/********************************************/
/* GET
/********************************************/

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/status");
    manager.status(function (data) {
        res_h.send(res, data);
    });

})

// GET /manager/info - Get manager info
router.get('/info', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/info");
    var args = ["-f", "get_ossec_init"]
    execute.exec(wazuh_control, args, function (data) {
        res_h.send(res, data);
    });

})

// GET /manager/configuration - Get manager configuration
router.get('/configuration', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration");

    allowed_fields = ['section', 'field'];
    filter = req_h.get_filter(req.query, allowed_fields);

    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
    else if (filter != null && filter.section != null && !validator.names(filter.section))
        res_h.bad_request("601", "Field: section", res);
    else if (filter != null && filter.field != null && !validator.names(filter.field))
        res_h.bad_request("601", "Field: field", res);
    else{
        var args = ["-f", "configuration.get_ossec_conf"]
        execute.exec(wazuh_control, args, function (json_output) {

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

                res_h.send(res, r_data_filtered);
            }
            else{
                res_h.send(res, json_output);
            }
        });
    }
})

// GET /manager/configuration/test - Test configuration
router.get('/configuration/test', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration/test");
    var args = ["-f", "configuration.check"]
    execute.exec(wazuh_control, args, function (data) {
        res_h.send(res, data);
    });
})

// GET /manager/stats - Stats
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");

    allowed_fields = ['date'];
    filter = req_h.get_filter(req.query, allowed_fields);

    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
    else{
        if(filter != null){
            if (!validator.dates(filter.date))
                res_h.bad_request("605", "Field: date", res);
            else{
                var date_arg = filter.date.substring(0, 4) + "," + filter.date.substring(4, 6) + "," + filter.date.substring(6, 8)
                var args = ["-f", "stats.totals", "-a", date_arg]
                execute.exec(wazuh_control, args, function (data) {
                    res_h.send(res, data);
                });

            }
        }
        else{
            var moment = require('moment');
            date = moment().format('YYYYMMDD')
            var date_arg = date.substring(0, 4) + "," + date.substring(4, 6) + "," + date.substring(6, 8)
            var args = ["-f", "stats.totals", "-a", date_arg]
            execute.exec(wazuh_control, args, function (data) {
                res_h.send(res, data);
            });
        }
    }
})

// GET /manager/stats/hourly - Stats hourly averages.
router.get('/stats/hourly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/hourly");
    var args = ["-f", "stats.hourly",]
    execute.exec(wazuh_control, args, function (data) {
        res_h.send(res, data);
    });
})

// GET /manager/stats/weekly - Stats weekly-hourly averages
router.get('/stats/weekly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/weekly");
    var args = ["-f", "stats.weekly",]
    execute.exec(wazuh_control, args, function (data) {
        res_h.send(res, data);
    });
})

/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/start");
    manager.start(function (data) {
        res_h.send(res, data);
    });
})

// PUT /manager/stop - Stop manager
router.put('/stop', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/stop");
    manager.stop(function (data) {
        res_h.send(res, data);
    });
})

// PUT /manager/restart - Restart manager
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/restart");
    manager.restart(function (data) {
        res_h.send(res, data);
    });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;
