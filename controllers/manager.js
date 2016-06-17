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


var res_h = require('../helpers/response_handler');
var logger = require('../helpers/logger');
var filter = require('../helpers/filters');
var execute = require('../helpers/execute');
var config = require('../config.js');
var wazuh_control = config.api_path + "/models/wazuh-control.py";
var express = require('express');
var router = express.Router();


/********************************************/
/* GET
/********************************************/

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/status");
    var args = ["-f", "manager.status"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/info - Get manager info
router.get('/info', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/info");
    var args = ["-f", "wazuh.get_ossec_init"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration - Get manager configuration
router.get('/configuration', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration");
    var args = []
    var filter0 = {'section':'names', 'field': 'names'};
    var filter1 = {'section':'names'};

    var filters = [filter0, filter1];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // section - field
                args = ["-f", "configuration.get_ossec_conf", "-a", req.query.section + "," + req.query.field];
                break;
            case 1:  // section
                args = ["-f", "configuration.get_ossec_conf", "-a", req.query.section];
                break;
        }
    }else { // No filter
        args = ["-f", "configuration.get_ossec_conf"]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration/test - Test configuration
router.get('/configuration/test', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration/test");
    var args = ["-f", "configuration.check"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats - Stats
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");

    var args = []
    var filter0 = {'date':'dates'};

    var filters = [filter0];

    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // date
                var date_arg = req.query.date.substring(0, 4) + "," + req.query.date.substring(4, 6) + "," + req.query.date.substring(6, 8)
                args = ["-f", "manager.stats.totals", "-a", date_arg]
                break;
        }
    }else { // No filter
        var moment = require('moment');
        date = moment().format('YYYYMMDD')
        var date_arg = date.substring(0, 4) + "," + date.substring(4, 6) + "," + date.substring(6, 8)
        args = ["-f", "manager.stats.totals", "-a", date_arg]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/hourly - Stats hourly averages.
router.get('/stats/hourly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/hourly");
    var args = ["-f", "manager.stats.hourly",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/weekly - Stats weekly-hourly averages
router.get('/stats/weekly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/weekly");
    var args = ["-f", "manager.stats.weekly",]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/start");
    var args = ["-f", "manager.start"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/stop - Stop manager
router.put('/stop', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/stop");
    var args = ["-f", "manager.stop"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /manager/restart - Restart manager
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/restart");
    var args = ["-f", "manager.restart"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;
