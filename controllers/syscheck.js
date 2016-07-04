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

// GET /syscheck/files
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/files");

    var data_request = {'function': '/syscheck/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'event':'names', 'file':'paths', 'filetype':'names', 'summary':'names'};

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
    if ('event' in req.query)
        data_request['arguments']['event'] = req.query.event;
    if ('file' in req.query)
        data_request['arguments']['filename'] = req.query.file;
    if ('filetype' in req.query)
        data_request['arguments']['filetype'] = req.query.filetype;
    if ('summary' in req.query)
        data_request['arguments']['summary'] = req.query.summary;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/files
router.get('/:agent_id/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/files");

    var data_request = {'function': '/syscheck/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'event':'names', 'filename':'paths', 'filetype':'names', 'summary':'names'};

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
    if ('event' in req.query)
        data_request['arguments']['event'] = req.query.event;
    if ('file' in req.query)
        data_request['arguments']['filename'] = req.query.file;
    if ('filetype' in req.query)
        data_request['arguments']['filetype'] = req.query.filetype;
    if ('summary' in req.query)
        data_request['arguments']['summary'] = req.query.summary;


    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /syscheck/:agent_id/last_scan - Syscheck last scan
router.get('/:agent_id/last_scan', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /syscheck/:agent_id/last_scan");

    var data_request = {'function': '/syscheck/:agent_id/last_scan', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* PUT
/********************************************/

// PUT /syscheck - Run syscheck in all agents.
router.put('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /syscheck/:agent_id - Run syscheck in the agent.
router.put('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /syscheck/:agent_id");

    var data_request = {'function': 'PUT/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /syscheck - Clear the database for all agent.
router.delete('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};
    data_request['arguments']['all_agents'] = 1;
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// DELETE /syscheck/:agent_id - Clear the database for the agent.
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /syscheck/:agent_id");

    var data_request = {'function': 'DELETE/syscheck', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, res))  // Filter with error
        return;
    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})



module.exports = router;
