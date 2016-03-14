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
var agent = require('../models/agent');
var res_h = require('../helpers/response_handler');
var req_h = require('../helpers/request_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');

/**
 *
 * GET /agents - Get agents list
 *   GET /agents?status=active - Get agents with status: Active, Disconnected, Never connected
 * GET /agents/:agent_id - Get Agent Info
 * GET /agents/:agent_id/key - Get Agent Key
 * PUT /agents/:agent_id/restart - Restart Agent
 * PUT /agents/:agent_name - Add Agent
 * POST /agents - Add Agent
 * DELETE /agents/:agent_id - Remove Agent
 *
**/


/********************************************/
/* GET
/********************************************/

// GET /agents - Get agents list
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents");
    
    filter = req_h.get_filter(req.query, ['status'], 1);
    
    if (filter == "bad_field")
        res_h.bad_request("604", "Allowed fields: status", res);
    else
        agent.all(filter, function (data) {
            res_h.cmd(data, res);
        });
})

// GET /agents/:agent_id - Get Agent Info
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id");
    
    if (validator.numbers(req.params.agent_id)){
        agent.info(req.params.agent_id, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// GET /agents/:agent_id/key - Get Agent Key
router.get('/:agent_id/key', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id/key");

    if (validator.numbers(req.params.agent_id)){
        agent.get_key(req.params.agent_id, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})


/********************************************/
/* PUT
/********************************************/

// PUT /agents/:agent_id/restart - Restart Agent
router.put('/:agent_id/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_id/restart");
    
    if (validator.numbers(req.params.agent_id)){
        agent.restart(req.params.agent_id, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }
})

// PUT /agents/:agent_name - Add Agent
router.put('/:agent_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_name");
    
    if (validator.names(req.params.agent_name)){
        agent.add(req.params.agent_name, "any", function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("601", "Field: agent_name", res);
    }
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /agents/:agent_id - Remove Agent
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /agents/:agent_id");
    
    if (validator.numbers(req.params.agent_id)){
        agent.remove(req.params.agent_id, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        res_h.bad_request("600", "Field: agent_id", res);
    }

})


/********************************************/
/* POST
/********************************************/

// POST /agents - Add Agent
router.post('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " POST /agents");
    var name = req.body.name;
    var ip = req.body.ip;

    if (validator.names(name) && validator.ips(ip)){
        agent.add(name, ip, function (data) {
            res_h.cmd(data, res);
        });
    }
    else{
        if (!validator.names(name))
            res_h.bad_request("601", "Field: name", res);
        else
            res_h.bad_request("606", "Field: ip", res);
    }

})



module.exports = router;
