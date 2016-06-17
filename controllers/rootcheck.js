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
var rootcheck = require('../models/rootcheck');
var filter = require('../helpers/filters');
var res_h = require('../helpers/response_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');


/********************************************/
/* GET
/********************************************/

// GET /rootcheck/:agent_id - Get rootcheck database
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rootcheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    rootcheck.print_db(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})

// GET /rootcheck/:agent_id/last_scan - Rootcheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rootcheck/:agent_id/last_scan");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    rootcheck.last_scan(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* PUT
/********************************************/

// PUT /rootcheck - Run rootcheck in all agents:
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /rootcheck");
    rootcheck.run("ALL", function (data) {
        res_h.send(res, data);
    });
})

// PUT /rootcheck/:agent_id - Run rootcheck in the agent.
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /rootcheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    rootcheck.run(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /rootcheck - Clear the database for all agent.
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /rootcheck");

    rootcheck.clear("ALL", function (data) {
        res_h.send(res, data);
    });
})

// DELETE /rootcheck/:agent_id - Clear the database for the agent.
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /rootcheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    rootcheck.clear(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})



module.exports = router;
