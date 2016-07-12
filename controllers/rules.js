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
 * @api {get} /rules Get all rules
 * @apiName GetRules
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters files by status.
 * @apiParam {String} [group] Filters file by group.
 * @apiParam {Range} [level] Filters file by level. level=2 or level=2-5.
 * @apiParam {String} [file] Filters by file name.
 * @apiParam {String} [pci] Filters by pci requirement.
 *
 * @apiDescription Returns all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules?offset=0&limit=2&pretty"
 *
 */
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules");

    var data_request = {'function': '/rules', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'group':'alphanumeric_param', 'level':'ranges', 'file':'alphanumeric_param', 'pci':'alphanumeric_param'};

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
    if ('group' in req.query)
        data_request['arguments']['group'] = req.query.group;
    if ('level' in req.query)
        data_request['arguments']['level'] = req.query.level;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;
    if ('pci' in req.query)
        data_request['arguments']['pci'] = req.query.pci;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {get} /rules/groups Get rule groups
 * @apiName GetRulesGroups
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the groups of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/groups?offset=0&limit=10&pretty"
 *
 */
router.get('/groups', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/groups");
    var data_request = {'function': '/rules/groups', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

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

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {get} /rules/pci Get rule pci requirements
 * @apiName GetRulesPci
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the PCI requirements of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/pci?offset=0&limit=10&pretty"
 *
 */
router.get('/pci', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/pci");
    var data_request = {'function': '/rules/pci', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

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

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {get} /rules/files Get files of rules
 * @apiName GetRulesFiles
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters files by status.
 *
 * @apiDescription Returns the files of all rules.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/files?offset=0&limit=10&pretty"
 *
 */
router.get('/files', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/files");

    var data_request = {'function': '/rules/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'download':'alphanumeric_param'};

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

    if ('download' in req.query)
        res_h.send_file(req.query.download, res);
    else
        execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})

/**
 * @api {get} /rules Get rules by id
 * @apiName GetRulesId
 * @apiGroup Info
 *
 * @apiParam {Number} id rule.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the begining to ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 *
 * @apiDescription Returns the rules with the specified id.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/rules/1002?pretty"
 *
 */
router.get('/:rule_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /rules/:rule_id");

    var data_request = {'function': '/rules', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param'};

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

    if (!filter.check(req.params, {'rule_id':'numbers'}, res))  // Filter with error
        return;

    data_request['arguments']['id'] = req.params.rule_id;

    execute.exec(wazuh_control, [], data_request, function (data) { res_h.send(res, data); });
})



module.exports = router;
