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



/**
 * @api {get} /manager/status Get manager status
 * @apiName GetManagerStatus
 * @apiGroup Info
 *
 * @apiDescription Returns the status of the manager processes.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/status?pretty"
 *
 */
router.get('/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/status");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/manager/status', 'arguments': {} };
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/status/:node_id Get manager status
 * @apiName GetManagerStatus
 * @apiGroup Info
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 *
 * @apiDescription Returns the select Manager processes that are running.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/status/192.168.56.102?pretty"
 *
 */
router.get('/status/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/status/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/status/:node_id', 'arguments': {}};
    var filters = {'node_id':'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/info Get manager information
 * @apiName GetManagerInfo
 * @apiGroup Info
 *
 * @apiDescription Returns basic information about manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/info?pretty"
 *
 */
router.get('/info', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/info");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/manager/info', 'arguments': {} };
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/info Get manager information
 * @apiName GetManagerInfo
 * @apiGroup Info
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiDescription Returns basic information about Manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/info/node02?pretty"
 *
 */
router.get('/info/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/info/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/info/:node_id', 'arguments': {}};
    var filters = {'node_id':'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/configuration Get manager configuration
 * @apiName GetManagerConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String} [section] Indicates the ossec.conf section: global, rules, syscheck, rootcheck, remote, alerts, command, active-response, localfile.
 * @apiParam {String} [field] Indicates a section child, e.g, fields for rule section are: include, decoder_dir, etc.
 *
 * @apiDescription Returns ossec.conf in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/configuration?section=global&pretty"
 *
 */
router.get('/configuration', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/configuration");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/configuration', 'arguments': {}};
    var filters = {'section':'names', 'field': 'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('section' in req.query)
        data_request['arguments']['section'] = req.query.section;
    if ('field' in req.query){
        if ('section' in req.query)
            data_request['arguments']['field'] = req.query.field;
        else
            res_h.bad_request(req, res, 604, "Missing field: 'section'");
    }
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/configuration/:node_id Get manager configuration
 * @apiName GetManagerConfiguration
 * @apiGroup Configuration
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiParam {String} [section] Indicates the ossec.conf section: global, rules, syscheck, rootcheck, remote, alerts, command, active-response, localfile.
 * @apiParam {String} [field] Indicates a section child, e.g, fields for rule section are: include, decoder_dir, etc.
 *
 * @apiDescription Returns ossec.conf in JSON format.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/configuration/node01?section=global&pretty"
 *
 */
router.get('/configuration/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/configuration/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/configuration/:node_id', 'arguments': {}};
    var filters = {'section':'names', 'field': 'names','node_id':'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('section' in req.query)
        data_request['arguments']['section'] = req.query.section;
    if ('field' in req.query){
        if ('section' in req.query)
            data_request['arguments']['field'] = req.query.field;
        else
            res_h.bad_request(req, res, 604, "Missing field: 'section'");
    }

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats Get manager stats
 * @apiName GetManagerStats
 * @apiGroup Stats
 *
 * @apiParam {String} [date] Selects the date for getting the statistical information. Format: YYYYMMDD
 *
 * @apiDescription Returns Wazuh statistical information for the current or specified date.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats?pretty"
 *
 */
router.get('/stats', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats', 'arguments': {}};
    var filters = {'date':'dates'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
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

    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/hourly Get manager stats by hour
 * @apiName GetManagerStatsHourly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per hour. Each number in the averages field represents the average of alerts per hour.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/hourly?pretty"
 *
 */
router.get('/stats/hourly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/hourly");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/manager/stats/hourly', 'arguments': {} };
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/hourly/:node_id Get manager stats by hour
 * @apiName GetManagerStatsHourly
 * @apiGroup Stats
 *
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiDescription Returns OSSEC statistical information per hour. Each item in averages field represents the average of alerts per hour.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/hourly/node01?pretty"
 *
 */
router.get('/stats/hourly/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/hourly/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/hourly/:node_id', 'arguments': {}};
    var filters = {'node_id':'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/weekly Get manager stats by week
 * @apiName GetManagerStatsWeekly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns Wazuh statistical information per week. Each number in the hours field represents the average alerts per hour for that specific day.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/weekly?pretty"
 *
 */
router.get('/stats/weekly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/weekly");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/manager/stats/weekly', 'arguments': {} };
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/weekly Get manager stats by week
 * @apiName GetManagerStatsWeekly
 * @apiGroup Stats
 *
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiDescription Returns OSSEC statistical information per week. Each item in hours field represents the average of alerts per hour and week day.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/weekly/192.168.56.102?pretty"
 *
 */
router.get('/stats/weekly/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/weekly/:node_id");

    req.apicacheGroup = "manager";
    var data_request = {'function': '/manager/stats/weekly/:node_id', 'arguments': {}};
    var filters = {'node_id':'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/:node_id Get manager stats
 * @apiName GetManagerStats
 * @apiGroup Stats
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiParam {String} [date] Selects the date for getting the statistical information. Format: YYYYMMDD
 *
 * @apiDescription Returns OSSEC statistical information of current date.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/node01?pretty"
 *
 */
router.get('/stats/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/:node_id', 'arguments': {}};
    var filters = {'date':'dates', 'node_id':'names'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
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

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/logs Get ossec.log
 * @apiName GetManagerLogs
 * @apiGroup Logs
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="all","error", "warning", "info"} [type_log] Filters by type of log.
 * @apiParam {String} [category] Filters by category of log.
 *
 * @apiDescription Returns the three last months of ossec.log.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/logs', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'type_log':'names', 'category': 'search_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('type_log' in req.query)
        data_request['arguments']['type_log'] = req.query.type_log;
    if ('category' in req.query)
        data_request['arguments']['category'] = req.query.category;

    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /manager/logs/summary Get summary of ossec.log
 * @apiName GetManagerLogsSummary
 * @apiGroup Logs
 *
 *
 * @apiDescription Returns a summary of the last three months of the ``ossec.log`` file.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs/summary?pretty"
 *
 */
router.get('/logs/summary', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs/summary");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/manager/logs/summary', 'arguments': {} };
    data_request['url'] = req.originalUrl
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /manager/logs/summary/:node_id Get summary of ossec.log
 * @apiName GetManagerLogsSummary
 * @apiGroup Logs
 *
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiDescription Returns a summary about the 3 last months of ossec.log.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs/summary/node02?pretty"
 *
 */
router.get('/logs/summary/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs/summary/:node_id");

    req.apicacheGroup = "manager";
    var data_request = {'function': '/manager/logs/summary/:node_id', 'arguments': {}};
    var filters = {'node_id':'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['node_id'] = req.params.node_id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /manager/logs/:node_id Get ossec.log
 * @apiName GetManagerLogs
 * @apiGroup Logs
 *
 *
 * @apiParam {String} [node_id] Node ID (IP or name)
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="all","error", "warning", "info"} [type_log] Filters by type of log.
 * @apiParam {String} [category] Filters by category of log.
 *
 * @apiDescription Returns the 3 last months of ossec.log.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs/:node01?offset=0&limit=5&pretty"
 *
 */
router.get('/logs/:node_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs/:node_id");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs/:node_id', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'type_log':'names', 'category': 'search_param', 'node_id':'names'};


    if (!filter.check(req.query, filters, req, res))  // Filter with error
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

    data_request['arguments']['node_id'] = req.params.node_id;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
