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
 * @api {get} /cluster/nodes Get nodes info
 * @apiName GetNodesInfo
 * @apiGroup cluster
 *
 * @apiParam {String} [node] Filters by node name.
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
    var filters = { 'node': 'alphanumeric_param'}

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('node' in req.query)
        data_request['arguments']['filter_node'] = req.query.node;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/healthcheck Show cluster health
 * @apiName GetHealthcheck
 * @apiGroup cluster
 *
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

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/agents Get info about agents in cluster
 * @apiName GetClusteragentsInfo
 * @apiGroup Nodes
 *
 * @apiParam {String} [node] Filters by node name.
 * @apiParam {String} [status] Filters by agents status.
 * *
 * @apiDescription Returns the state of each agent and the manager it's reporting to in the cluster
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/agents?pretty"
 *
 */
router.get('/agents', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/agents");

    req.apicacheGroup = "cluster";

    var data_request = { 'function': '/cluster/agents', 'arguments': {} };
    var filters = { 'node': 'alphanumeric_param', 'status': 'alphanumeric_param' }

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('node' in req.query)
        data_request['arguments']['filter_node'] = req.query.node;
    if ('status' in req.query)
        data_request['arguments']['filter_status'] = req.query.status;

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
