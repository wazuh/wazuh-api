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

// GET /rootcheck/:agent_id - Get rootcheck database
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rootcheck/:agent_id");

    var data_request = {'function': '/rootcheck/:agent_id', 'arguments': {}};

    var filters = {'status': 'names', 'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /rootcheck/:agent_id/last_scan - Rootcheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rootcheck/:agent_id/last_scan");

    var data_request = {'function': '/rootcheck/:agent_id/last_scan', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* PUT
/********************************************/

// PUT /rootcheck - Run rootcheck in all agents:
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /rootcheck");

    var data_request = {'function': 'PUT/rootcheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /rootcheck/:agent_id - Run rootcheck in the agent.
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /rootcheck/:agent_id");

    var data_request = {'function': 'PUT/rootcheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /rootcheck - Clear the database for all agent.
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /rootcheck");

    var data_request = {'function': 'DELETE/rootcheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// DELETE /rootcheck/:agent_id - Clear the database for the agent.
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /rootcheck/:agent_id");

    var data_request = {'function': 'DELETE/rootcheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})



module.exports = router;
