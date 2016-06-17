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
var syscheck = require('../models/syscheck');
var res_h = require('../helpers/response_handler');
var logger = require('../helpers/logger');
var filter = require('../helpers/filters');

check_agent_and_filename = function(req, res){
    var filename = null

    // Params
    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    // Query
    var filters = [{'filename':'paths'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // filename
                filename = req.query.filename;
                break;
        }
    }

    return filename;
}

/********************************************/
/* GET
/********************************************/

// GET /syscheck/:agent_id/files/changed - List modified files for the agent.
router.get('/:agent_id/files/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed");
    var filename = this.check_agent_and_filename(req, res);
    if (filename == -1)
        return;

    syscheck.files_changed(req.params.agent_id, filename, function (data) {
        res_h.send(res, data);
    });
})

// GET /syscheck/:agent_id/files/changed/total - Number of modified files for the agent.
router.get('/:agent_id/files/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed/total");
    var filename = this.check_agent_and_filename(req, res);
    if (filename == -1)
        return;

    syscheck.files_changed_total(req.params.agent_id, filename, function (data) {
        res_h.send(res, data);
    });
})

// GET /syscheck/:agent_id/registry/changed - List modified registry entries
router.get('/:agent_id/registry/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed");

    var filename = this.check_agent_and_filename(req, res);
    if (filename == -1)
        return;

    syscheck.registry_changed(req.params.agent_id, filename, function (data) {
        res_h.send(res, data);
    });
})

// GET /syscheck/:agent_id/registry/changed/total - Number of modified registry entries
router.get('/:agent_id/registry/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed/total");

    var filename = this.check_agent_and_filename(req, res);
    if (filename == -1)
        return;

    syscheck.registry_changed_total(req.params.agent_id, filename, function (data) {
        res_h.send(res, data);
    });
})

// GET /syscheck/:agent_id/last_scan - Syscheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    syscheck.last_scan(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });

})


/********************************************/
/* PUT
/********************************************/

// PUT /syscheck - Run syscheck in all agents.
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck");
    syscheck.run("ALL", function (data) {
        res_h.send(res, data);
    });
})

// PUT /syscheck/:agent_id - Run syscheck in the agent.
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    syscheck.run(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /syscheck - Clear the database for all agent.
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck");
    syscheck.clear("ALL", function (data) {
        res_h.send(res, data);
    });
})

// DELETE /syscheck/:agent_id - Clear the database for the agent.
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    syscheck.clear(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})



module.exports = router;
