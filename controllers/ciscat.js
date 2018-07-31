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
 * @api {get} /ciscat/:agent_id/results Get CIS-CAT results from an agent
 * @apiName GetCiscat_agent
 * @apiGroup Results
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {Number} [benchmark] Filters by process pid.
 * @apiParam {String} [profile] Filters by process egroup.
 * @apiParam {String} [pass] Filters by process euser.
 * @apiParam {String} [fail] Filters by process fgroup.
 * @apiParam {Number} [error] Filters by process nlwp.
 * @apiParam {Number} [notchecked] Filters by process pgrp.
 * @apiParam {Number} [unknown] Filters by process priority.
 * @apiParam {String} [score] Filters by process rgroup.
 *
 * @apiDescription Returns the agent's ciscat results info
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/ciscat/000/results?pretty&limit=2&offset=10&sort=-name"
 *
 */
router.get('/:agent_id/results', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /ciscat/:agent_id/results");

    var data_request = { 'function': '/ciscat/:agent_id/results', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',

        'benchmark': 'alphanumeric_param', 'profile': 'alphanumeric_param', 'pass': 'alphanumeric_param',
        'fail': 'alphanumeric_param',
        'error': 'numbers', 'notchecked': 'numbers',
        'unknown': 'numbers', 'score': 'numbers'
    };


    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('benchmark' in req.query)
        data_request['arguments']['benchmark'] = filter.search_param_to_json(req.query.benchmark);
    if ('profile' in req.query)
        data_request['arguments']['profile'] = filter.search_param_to_json(req.query.profile);
    if ('pass' in req.query)
        data_request['arguments']['pass'] = filter.search_param_to_json(req.query.pass);
    if ('fail' in req.query)
        data_request['arguments']['fail'] = filter.search_param_to_json(req.query.fail);
    if ('error' in req.query)
        data_request['arguments']['error'] = filter.search_param_to_json(req.query.error);
    if ('notchecked' in req.query)
        data_request['arguments']['notchecked'] = filter.search_param_to_json(req.query.notchecked);
    if ('unknown' in req.query)
        data_request['arguments']['unknown'] = filter.search_param_to_json(req.query.unknown);
    if ('score' in req.query)
        data_request['arguments']['score'] = filter.search_param_to_json(req.query.score);

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
