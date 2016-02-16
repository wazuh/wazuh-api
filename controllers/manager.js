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

/**
 * GET /manager/status - Get manager status
 * GET /manager/settings - Get manager settings
 * GET /manager/settings?section=rules - Get rules in ossec.conf
 * GET /manager/testconfig - Test config
 * GET /manager/stats - Stats Today
 * GET /manager/stats/hourly - Stats hourly averages.
 * GET /manager/stats/weekly - Stats weekly-hourly averages
 * GET /manager/stats/YYYYMMDD - Stats YYYYMMDD
 *
 * PUT /manager/start - Start manager
 * PUT /manager/stop - Stop manager
 * PUT /manager/restart - Restart manager
 *
**/


/********************************************/
/* GET
/********************************************/

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/status");
    manager.status(function (data) {
        res_h.cmd(data, res);
    });
    
})

// GET /manager/settings - Get manager settings
router.get('/settings', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/settings");

    filter = req_h.get_filter(req.query, ['section', 'field'], 2);
    
    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: section, field", res);
    else
        manager.settings(filter, function (data) {
            res_h.cmd(data, res);
        });
})

// GET /manager/testconfig - Test config
router.get('/testconfig', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/testconfig");
    manager.testconfig(function (data) {
        res_h.cmd(data, res);
    });
    
})

// GET /manager/stats - Stats Today
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");
    manager.stats("today", function (data) {
        res_h.cmd(data, res);
    });
})

// GET /manager/stats/hourly - Stats hourly averages.
router.get('/stats/hourly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/hourly");
    manager.stats("hourly", function (data) {
        res_h.cmd(data, res);
    });
})

// GET /manager/stats/weekly - Stats weekly-hourly averages
router.get('/stats/weekly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/weekly");
    manager.stats("weekly", function (data) {
        res_h.cmd(data, res);
    });
})

// GET /manager/stats/YYYYMMDD - Stats YYYYMMDD
router.get('/stats/:date', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/YYYYMMDD");
    
    if (validator.dates(req.params.date)){
        manager.stats(req.params.date, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("605", "date", res);
    }
})

/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/start");
    manager.start(function (data) {
        res_h.cmd(data, res);
    });
})

// PUT /manager/stop - Stop manager
router.put('/stop', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/stop");
    manager.stop(function (data) {
        res_h.cmd(data, res);
    });
})

// PUT /manager/restart - Restart manager
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/restart");
    manager.restart(function (data) {
        res_h.cmd(data, res);
    });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;