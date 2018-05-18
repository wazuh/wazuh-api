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
 * @api {get} /cluster/node Get local node info
 * @apiName GetLocalNodeInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the local node info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node?pretty"
 *
 */
router.get('/node', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node");
    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/node', 'arguments': {} };

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/nodes Get nodes info
 * @apiName GetNodesInfo
 * @apiGroup cluster
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * *
 * @apiDescription Returns the nodes info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes?pretty"
 *
 */
router.get('/nodes', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes");

    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/nodes', 'arguments': {} };
    var filters = { 'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'type': 'alphanumeric_param', 'select': 'select_param' }

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
    if ('type' in req.query)
        data_request['arguments']['filter_type'] = req.query.type
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/nodes/:node_name Get node info
 * @apiName GetNodeInfo
 * @apiGroup cluster
 *
 * @apiDescription Returns the node info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes/node01?pretty"
 *
 */
router.get('/nodes/:node_name', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes/:node_name");
    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/nodes/:node_name', 'arguments': {} };
    var filters = {
        'select': 'select_param'
    }

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;
    if (!filter.check(req.params, { 'node_name': 'names' }, req, res))  // Filter with error
        return;

    data_request['arguments']['filter_node'] = req.params.node_name;
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/healthcheck Show cluster health
 * @apiName GetHealthcheck
 * @apiGroup cluster
 *
 * @apiParam {String} [node] Filter information by node name.
 * *
 * @apiDescription Show cluster health
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/healthcheck?pretty"
 *
 */
router.get('/healthcheck', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/healthcheck");

    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/healthcheck', 'arguments': {} };
    var filters = { 'node': 'names'};

    if (!filter.check(req.params, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['filter_node'] = req.query.node;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /cluster/status Get info about cluster status
 * @apiName GetClusterstatus
 * @apiGroup Status
 *
 * @apiDescription Returns whether the cluster is enabled or disabled
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/status?pretty"
 *
 */
router.get('/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/status");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/status', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/config Get the cluster configuration
 * @apiName GetClusterconfig
 * @apiGroup config
 *
 * @apiDescription Returns the cluster configuration
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/config?pretty"
 *
 */
router.get('/config', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/config");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/config', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
