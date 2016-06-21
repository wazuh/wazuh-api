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


var router = require('express').Router();

/********************************************/
/* GET
/********************************************/

// GET /syscheck/:agent_id/files/changed - List modified files for the agent.
router.get('/:agent_id/files/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed");
    var args = []

    // Params
    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    // Query
    var filters = [{'filename':'paths'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // filename
                args = ["-f", "/syscheck/:agent_id/files/changed", "-a", req.params.agent_id + "," + req.query.filename]
                break;
        }
    }
    else { // No filter
        args = ["-f", "/syscheck/:agent_id/files/changed", "-a", req.params.agent_id]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/files/changed/total - Number of modified files for the agent.
router.get('/:agent_id/files/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed/total");
    var args = []

    // Params
    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    // Query
    var filters = [{'filename':'paths'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // filename
                args = ["-f", "/syscheck/:agent_id/files/changed/total", "-a", req.params.agent_id + "," + req.query.filename]
                break;
        }
    }
    else { // No filter
        args = ["-f", "/syscheck/:agent_id/files/changed/total", "-a", req.params.agent_id]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/registry/changed - List modified registry entries
router.get('/:agent_id/registry/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed");

    // Params
    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    // Query
    var filters = [{'filename':'paths'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // filename
                args = ["-f", "/syscheck/:agent_id/registry/changed", "-a", req.params.agent_id + "," + req.query.filename]
                break;
        }
    }
    else { // No filter
        args = ["-f", "/syscheck/:agent_id/registry/changed", "-a", req.params.agent_id]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/registry/changed/total - Number of modified registry entries
router.get('/:agent_id/registry/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed/total");

    // Params
    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    // Query
    var filters = [{'filename':'paths'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // filename
                args = ["-f", "/syscheck/:agent_id/registry/changed/total", "-a", req.params.agent_id + "," + req.query.filename]
                break;
        }
    }
    else { // No filter
        args = ["-f", "/syscheck/:agent_id/registry/changed/total", "-a", req.params.agent_id]
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/last_scan - Syscheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    var args = ["-f", "/syscheck/:agent_id/last_scan", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


/********************************************/
/* PUT
/********************************************/

// PUT /syscheck - Run syscheck in all agents.
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck");

    var args = ["-f", "PUT/syscheck", "-a", "ALL"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /syscheck/:agent_id - Run syscheck in the agent.
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    var args = ["-f", "PUT/syscheck", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /syscheck - Clear the database for all agent.
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck");
    var args = ["-f", "DELETE/syscheck", "-a", "ALL"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// DELETE /syscheck/:agent_id - Clear the database for the agent.
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return -1;

    var args = ["-f", "DELETE/syscheck", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})



module.exports = router;
