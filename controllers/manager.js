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
 * @apiDescription Returns the Manager processes that are running.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/status?pretty"
 *
 */
router.get('/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/status");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/status', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/info Get manager information
 * @apiName GetManagerInfo
 * @apiGroup Info
 *
 * @apiDescription Returns basic information about Manager.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/info?pretty"
 *
 */
router.get('/info', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/info");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/info', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
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
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats Get manager stats
 * @apiName GetManagerStats
 * @apiGroup Stats
 *
 * @apiParam {String} [date] Selects the date for getting the statistical information. Format: YYYYMMDD
 *
 * @apiDescription Returns OSSEC statistical information of current date.
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

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/hourly Get manager stats by hour
 * @apiName GetManagerStatsHourly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns OSSEC statistical information per hour. Each item in averages field represents the average of alerts per hour.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/hourly?pretty"
 *
 */
router.get('/stats/hourly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/hourly");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/hourly', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/stats/weekly Get manager stats by week
 * @apiName GetManagerStatsWeekly
 * @apiGroup Stats
 *
 *
 * @apiDescription Returns OSSEC statistical information per week. Each item in hours field represents the average of alerts per hour and week day.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/stats/weekly?pretty"
 *
 */
router.get('/stats/weekly', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/stats/weekly");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/stats/weekly', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/logs Get ossec.log
 * @apiName GetManagerLogs
 * @apiGroup Logs
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {string="all","error", "info"} [type_log] Filters by type of log.
 * @apiParam {string} [category] Filters by category of log.
 *
 * @apiDescription Returns the 3 last months of ossec.log.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs?offset=0&limit=5&pretty"
 *
 */
router.get('/logs', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'type_log':'names', 'category': 'names'};

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

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /manager/logs/summary Get summary of ossec.log
 * @apiName GetManagerLogsSummary
 * @apiGroup Logs
 *
 *
 * @apiDescription Returns a summary about the 3 last months of ossec.log.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/manager/logs/summary?pretty"
 *
 */
router.get('/logs/summary', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /manager/logs/summary");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/manager/logs/summary', 'arguments': {}};
    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
