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
var filter = require('../helpers/filters');
var logger = require('../helpers/logger');
var config = require('../config.js');


/********************************************/
/* GET
/********************************************/

// GET /agents - Get agents list
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents");
    var status = null;

    var filters = [{'status':'alphanumeric_param'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                status = req.query.status;
                break;
        }
    }

    agent.all(status, function (data) {
        res_h.send(res, data);
    });
})

// GET /agents/total - Get number of agents
router.get('/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/total");
    var status = null;

    var filters = [{'status':'alphanumeric_param'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                status = req.query.status;
                break;
        }
    }

    agent.total(status, function (data) {
        res_h.send(res, data);
    });
})

// GET /agents/:agent_id - Get Agent Info
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    agent.info(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });

})

// GET /agents/:agent_id/key - Get Agent Key
router.get('/:agent_id/key', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id/key");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    agent.get_key(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* PUT
/********************************************/

// PUT /agents/:agent_id/restart - Restart Agent
router.put('/:agent_id/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_id/restart");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    agent.restart(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})

// PUT /agents/:agent_name - Add Agent
router.put('/:agent_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_name");

    var check_filter = filter.check(req.params, [{'agent_name':'names'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    agent.add(req.params.agent_name, "any", function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /agents/:agent_id - Remove Agent
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /agents/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    agent.remove(req.params.agent_id, function (data) {
        res_h.send(res, data);
    });
})


/********************************************/
/* POST
/********************************************/

// POST /agents - Add Agent
router.post('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " POST /agents");

    // If not IP set, we will use source IP.
    var ip = req.body.ip;
    if ( !ip ){
        // If we hare behind a proxy server, use headers.
        if (config.BehindProxyServer.toLowerCase() == "yes")
            ip = req.headers['x-forwarded-for'];
        else
            ip = req.connection.remoteAddress;

        // Extract IPv4 from IPv6 hybrid notation
        if (ip.indexOf("::ffff:") > -1) {
            var ipFiltered = ip.split(":");
            ip = ipFiltered[ipFiltered.length-1];
            logger.debug("Hybrid IPv6 IP filtered: " + ip);
        }
        logger.debug("Add agent with automatic IP: " + ip);
    }
    req.body.ip = ip;

    var filters = [{'name':'names', 'ip':'ips'}];
    var check_filter = filter.check(req.body, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                agent.add(req.body.name, req.body.ip, function (data) {
                    res_h.send(res, data);
                });
                break;
        }
    }
})



module.exports = router;
