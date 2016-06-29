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

// GET /agents - Get agents list
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents");

    var data_request = {'function': '/agents', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'status':'alphanumeric_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /agents/total - Get number of agents
router.get('/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/total");

    var data_request = {'function': '/agents/total', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'status':'alphanumeric_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /agents/:agent_id - Get Agent Info
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id");

    var data_request = {'function': '/agents/:agent_id', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });

})

// GET /agents/:agent_id/key - Get Agent Key
router.get('/:agent_id/key', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id/key");

    var data_request = {'function': '/agents/:agent_id/key', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* PUT
/********************************************/

// PUT /agents/restart - Restart All Agents
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/restart");

    var data_request = {'function': 'PUT/agents/restart', 'arguments': {}};

    data_request['arguments']['restart_all'] = 'True';

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /agents/:agent_id/restart - Restart Agent
router.put('/:agent_id/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_id/restart");

    var data_request = {'function': 'PUT/agents/:agent_id/restart', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /agents/:agent_name - Add Agent
router.put('/:agent_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_name");

    var data_request = {'function': 'PUT/agents/:agent_name', 'arguments': {}};

    if (!filter.check(req.params, {'agent_name':'names'}, res))  // Filter with error
        return;

    data_request['arguments']['name'] = req.params.agent_name;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /agents/:agent_id - Remove Agent
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /agents/:agent_id");

    var data_request = {'function': 'DELETE/agents/:agent_id', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
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

    var data_request = {'function': 'POST/agents', 'arguments': {}};
    var filters = {'name':'names', 'ip':'ips'};

    if (!filter.check(req.body, filters, res))  // Filter with error
        return;

    data_request['arguments']['ip'] = req.body.ip;

    if ('name' in req.body){
        data_request['arguments']['name'] = req.body.name;
        execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
    }else
        res_h.bad_request(604, "Missing field: 'name'", res);
})



module.exports = router;
