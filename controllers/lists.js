/**
 * Wazuh RESTful API
 * Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


var router = require('express').Router();

/**
 * @api {get} /lists Get all lists
 * @apiName GetList
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [file] Filters by filename.
 * @apiParam {String} [path] Filters by path.
 * @apiParam {String="enabled","disabled", "all"} [status] Filters the decoders by status.
 *
 * @apiDescription Returns all decoders included in ossec.conf.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/lists?pretty&path=etc/lists/audit-keys"
 *
 */
router.get('/', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /lists");

    req.apicacheGroup = "decoders";

    var data_request = {'function': '/lists', 'arguments': {}};
    //var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'path':'paths', 'file':'alphanumeric_param'};

    //if (!filter.check(req.query, filters, req, res))  // Filter with error
    //    return;

    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    /*
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    */

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /lists/paths Get paths from all lists
 * @apiName GetListPath
 * @apiGroup Info
 *
 * @apiDescription Returns the path from all lists.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/lists/paths?pretty"
 *
 */
router.get('/paths', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /lists/paths");

    req.apicacheGroup = "decoders";

    var data_request = {'function': '/lists/paths', 'arguments': {}};
    //var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'path':'paths', 'file':'alphanumeric_param'};

    //if (!filter.check(req.query, filters, req, res))  // Filter with error
    //    return;

    /*
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    */

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
