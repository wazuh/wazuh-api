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

// GET /manager/status - Get manager status
router.get('/status', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/status");

    var data_request = {'function': '/manager/status', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/info - Get manager info
router.get('/info', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/info");

    var data_request = {'function': '/manager/info', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration - Get manager configuration
router.get('/configuration', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration");

    var data_request = {'function': '/manager/configuration', 'arguments': {}};
    var filters = {'section':'names', 'field': 'names'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('section' in req.query)
        data_request['arguments']['section'] = req.query.section;
    if ('field' in req.query){
        if ('section' in req.query)
            data_request['arguments']['field'] = req.query.field;
        else
            res_h.bad_request(604, "Missing field: 'section'", res);
    }
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/configuration/test - Test configuration
router.get('/configuration/test', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/configuration/test");

    var data_request = {'function': '/manager/configuration/test', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/stats - Stats
router.get('/stats', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats");

    var data_request = {'function': '/manager/stats', 'arguments': {}};
    var filters = {'date':'dates'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('date' in req.query){
        data_request['arguments']['year'] = req.query.date.substring(0, 4);
        data_request['arguments']['month'] = req.query.date.substring(4, 6);
        data_request['arguments']['day'] = req.query.date.substring(6, 8);
    }
    else{
        var moment = require('moment');
        date = moment().format('YYYYMMDD')
        data_request['arguments']['year'] = date.substring(0, 4);
        data_request['arguments']['month'] = date.substring(4, 6);
        data_request['arguments']['day'] = date.substring(6, 8);
    }

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/hourly - Stats hourly averages.
router.get('/stats/hourly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/hourly");

    var data_request = {'function': '/manager/stats/hourly', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/stats/weekly - Stats weekly-hourly averages
router.get('/stats/weekly', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/stats/weekly");

    var data_request = {'function': '/manager/stats/weekly', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/update-ruleset/backups - Get ruleset backups
router.get('/update-ruleset/backups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/update-ruleset/backups");

    var data_request = {'function': '/manager/update-ruleset/backups', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/logs - Logs
router.get('/logs', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/logs");

    var data_request = {'function': '/manager/logs', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'type_log':'names', 'category': 'names'};

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
    if ('type_log' in req.query)
        data_request['arguments']['type_log'] = req.query.type_log;
    if ('category' in req.query)
        data_request['arguments']['category'] = req.query.category;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// GET /manager/logs/summary - ossec.log summary
router.get('/logs/summary', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /manager/logs/summary");

    var data_request = {'function': '/manager/logs/summary', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/********************************************/
/* PUT
/********************************************/
// PUT /manager/start - Start manager
router.put('/start', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/start");

    var data_request = {'function': 'PUT/manager/start', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /manager/stop - Stop manager
router.put('/stop', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/stop");

    var data_request = {'function': 'PUT/manager/stop', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /manager/restart - Restart manager
router.put('/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/restart");

    var data_request = {'function': 'PUT/manager/restart', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /manager/update-ruleset - update ruleset
router.put('/update-ruleset', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /manager/update-ruleset");

    var data_request = {'function': 'PUT/manager/update-ruleset', 'arguments': {}};
    var filters = {'type':'names', 'force': 'names'};

    if (!filter.check(req.query, filters, res))  // Filter with error
        return;

    if ('type' in req.query)
        data_request['arguments']['type'] = req.query.type;
    if ('force' in req.query)
        if (req.query.force == "yes")
            data_request['arguments']['force'] = "True";

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

// PUT /manager/update-ruleset/backups/:id- backup ruleset
router.put('/update-ruleset/backups/:id', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT/manager/update-ruleset/backups/:id");

    var data_request = {'function': 'PUT/manager/update-ruleset/backups/:id', 'arguments': {}};

    if (!filter.check(req.params, {'id':'names'}, res))  // Filter with error
        return;

    data_request['arguments']['date'] = req.params.id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/********************************************/
/* DELETE
/********************************************/


/********************************************/
/* PATCH
/********************************************/



module.exports = router;
