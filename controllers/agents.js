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
var rh = require('../helpers/response_handler');
var logger = require('../helpers/logger');
var validator = require('../helpers/input_validation');

/**
 * GET /agents - Get agents list
 * GET /agents/:agent_id/key - Get Agent Key
 * GET /agents/:agent_id - Get Agent Info
 *
 * PUT /agents/:agent_name - Add Agent
 * PUT /agents/:agent_id/restart - Restart Agent
 * PUT /agents/sysrootcheck/restart - Restart syscheck/rootcheck in all agents:
 * PUT /agents/:agent_id/sysrootcheck/restart - Restart syscheck/rootcheck in a agents
 *
**/

/********************************************/
/* GET
/********************************************/

// Get agents List: /agents
router.get('/', function(req, res) {
    logger.log(req.host + " GET /agents");
    agent.all(function (data) {
        rh.cmd(data, res);
    });
})

// Get Agent Key: /agents/:agent_id/key
router.get('/:agent_id/key', function(req, res) {
    logger.log(req.host + " GET /agents/:agent_id/key");

    if (validator.numbers(req.params.agent_id)){
        agent.get_key(req.params.agent_id, function (data) {
            rh.cmd(data, res);
        });
    }
    else{
        rh.bad_request("600", "agent_id", res);
    }
})

// Get Agent Info: /agents/:agent_id
router.get('/:agent_id', function(req, res) {
    logger.log(req.host + " GET /agents/:agent_id");
    
    if (validator.numbers(req.params.agent_id)){
        agent.info(req.params.agent_id, function (data) {
            rh.cmd(data, res);
        });
    }
    else{
        rh.bad_request("600", "agent_id", res);
    }
})


/********************************************/
/* PUT
/********************************************/

// Add Agent: /agents/:agent_name
router.put('/:agent_name', function(req, res) {
    logger.log(req.host + " PUT /agents/:agent_name");
    
    if (validator.names(req.params.agent_name)){
        agent.add(req.params.agent_name, function (data) {
            rh.cmd(data, res);
        });
    }
    else{
        rh.bad_request("601", "agent_name", res);
    }

})

// Restart Agent: /agents/:agent_id/restart
router.put('/:agent_id/restart', function(req, res) {
    logger.log(req.host + " PUT /agents/:agent_id/restart");
    
    if (validator.numbers(req.params.agent_id)){
        agent.restart(req.params.agent_id, function (data) {
            rh.cmd(data, res);
        });
    }
    else{
        rh.bad_request("600", "agent_id", res);
    }
})

// Restart syscheck/rootcheck in all agents: /agents/sysrootcheck/restart
router.put('/sysrootcheck/restart', function(req, res) {
    logger.log(req.host + " PUT /agents/sysrootcheck/restart");
    agent.restart_sysrootcheck("ALL", function (data) {
        rh.cmd(data, res);
    });
})

// Restart syscheck/rootcheck in a agents: /agents/:agent_id/sysrootcheck/restart
router.put('/:agent_id/sysrootcheck/restart', function(req, res) {
    logger.log(req.host + " PUT /agents/:agent_id/sysrootcheck/restart");

    if (validator.restart_sysrootcheck(req.params.agent_id)){
        agent.restart_sysrootcheck(req.params.agent_id, function (data) {
            rh.cmd(data, res);
        });
    }
    else{
        rh.bad_request("600", "agent_id", res);
    }
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;
