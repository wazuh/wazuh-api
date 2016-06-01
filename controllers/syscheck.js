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
var req_h = require('../helpers/request_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');

/**
 *
 * GET /syscheck/:agent_id/files/changed - List modified files for the agent.
 *   GET /syscheck/:agent_id/files/changed?filename=name - Prints information about a modified file.
 * GET /syscheck/:agent_id/files/changed/total - Number of modified files for the agent.
 *   GET /syscheck/:agent_id/files/changed/total?filename=name - Number of modified files for the agent matching the filename param.
 * GET /syscheck/:agent_id/registry/changed - List modified registry entries
 *  filter: filename
 * GET /syscheck/:agent_id/registry/changed/total - Number of modified registry entries
 *  filter: filename
 * GET /syscheck/:agent_id/last_scan - Syscheck last scan
 * PUT /syscheck - Run syscheck in all agents.
 * PUT /syscheck/:agent_id - Run syscheck in the agent.
 * DELETE /syscheck - Clear the database for all agent.
 * DELETE /syscheck/:agent_id - Clear the database for the agent.
 *
 * ToDo:
 *  GET /syscheck/:agent_id/files
 *  GET /syscheck/:agent_id/registry
 *  GET /syscheck/:agent_id/registry/changed
 *
**/



/********************************************/
/* GET
/********************************************/

// GET /syscheck/:agent_id/files/changed - List modified files for the agent.
router.get('/:agent_id/files/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed");

    if (validator.numbers(req.params.agent_id)){
        allowed_fields = ['filename'];
        filter = req_h.get_filter(req.query, allowed_fields);

        if (filter == "bad_field")
            res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
        else if(filter != null && !validator.paths(filter.filename))
                res_h.bad_request("608", "Field: filename", res);
        else
            syscheck.files_changed(req.params.agent_id, filter, function (data) {
                res_h.send(res, data);
            });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// GET /syscheck/:agent_id/files/changed/total - Number of modified files for the agent.
router.get('/:agent_id/files/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files/changed/total");

    if (validator.numbers(req.params.agent_id)){
        allowed_fields = ['filename'];
        filter = req_h.get_filter(req.query, allowed_fields);

        if (filter == "bad_field")
            res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
        else if(filter != null && !validator.paths(filter.filename))
                res_h.bad_request("608", "Field: filename", res);
        else
            syscheck.files_changed_total(req.params.agent_id, filter, function (data) {
                res_h.send(res, data);
            });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// GET /syscheck/:agent_id/registry/changed - List modified registry entries
router.get('/:agent_id/registry/changed', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed");

    if (validator.numbers(req.params.agent_id)){
        allowed_fields = ['filename'];
        filter = req_h.get_filter(req.query, allowed_fields);

        if (filter == "bad_field")
            res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
        else if(filter != null && !validator.paths(filter.filename))
                res_h.bad_request("608", "Field: filename", res);
        else
            syscheck.registry_changed(req.params.agent_id, filter, function (data) {
                res_h.send(res, data);
            });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// GET /syscheck/:agent_id/registry/changed/total - Number of modified registry entries
router.get('/:agent_id/registry/changed/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/registry/changed/total");

    if (validator.numbers(req.params.agent_id)){
        allowed_fields = ['filename'];
        filter = req_h.get_filter(req.query, allowed_fields);

        if (filter == "bad_field")
            res_h.bad_request("604", "Allowed fields: " + allowed_fields, res);
        else if(filter != null && !validator.paths(filter.filename))
                res_h.bad_request("608", "Field: filename", res);
        else
            syscheck.registry_changed_total(req.params.agent_id, filter, function (data) {
                res_h.send(res, data);
            });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// GET /syscheck/:agent_id/last_scan - Syscheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    if (validator.numbers(req.params.agent_id)){
        syscheck.last_scan(req.params.agent_id, function (data) {
            res_h.send(res, data);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
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

    if (validator.numbers(req.params.agent_id)){
        syscheck.run(req.params.agent_id, function (data) {
            res_h.send(res, data);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
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

    if (validator.numbers(req.params.agent_id)){
        syscheck.clear(req.params.agent_id, function (data) {
            res_h.send(res, data);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }

})



module.exports = router;
