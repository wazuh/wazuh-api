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
 * @api {get} /report/distinct/agents Get distinct fields in agents
 * @apiName GetdistinctAgents
 * @apiGroup Agents
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * 
 * @apiDescription Returns all the different combinations that agents have for the selected fields. It also indicates the total number of agents that have each combination.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/report/distinct/agents?pretty"
 *
 */
router.get('/distinct/agents', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /report/distinct/agents");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/report/distinct/agents', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'select': 'select_param','sort': 'sort_param',
        'search': 'search_param'
    };
    
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
