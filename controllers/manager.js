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
 *
 * PUT /manager/start - Start manager
 * PUT /manager/stop - Stop manager
 * PUT /manager/restart - Restart manager
 * GET /manager/status - Get manager status
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
        res_h.cmd(data, res);
    });
    
})

// GET /manager/configuration - Get manager configuration
router.get('/configuration', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration");

    filter = req_h.get_filter(req.query, ['section', 'field'], 2);
    
    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: section, field", res);
    else
        manager.config(filter, function (data) {
            res_h.cmd(data, res);
        });
})

// GET /manager/configuration/test - Test configuration
router.get('/configuration/test', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration/test");
    manager.testconfig(function (data) {
        res_h.cmd(data, res);
    });
    
})

// GET /manager/stats - Stats
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");

    filter = req_h.get_filter(req.query, ['date'], 1);
    
    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: date", res);
    else{
        if(filter != null){
            if (validator.dates(filter.date)){
                manager.stats(filter.date, function (data) {
                    res_h.cmd(data, res);
                });
            }
            else{
                res_h.bad_request("605", "Field: date", res);
            }
        }
        else{
            manager.stats("today", function (data) {
                res_h.cmd(data, res);
            });
        }
    }
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