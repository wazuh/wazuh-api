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
 * @apiGroup Nodes
 *
 * @apiDescription Returns the Nodes info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes"
 *
 */
router.get('/nodes', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/nodes', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/nodes/elected_master Get elected master
 * @apiName GetElectedMaster
 * @apiGroup Nodes
 *
 * @apiDescription Returns the elected master
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/nodes/elected_master?pretty"
 *
 */
router.get('/nodes/elected_master', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/nodes/elected_master");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/nodes/elected_master', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/node Get node info
 * @apiName GetNodeInfo
 * @apiGroup Node
 *
 * @apiDescription Returns the Node info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node"
 *
 */
router.get('/node', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/node', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/files Get info about files in cluster
 * @apiName GetClusterFilesInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the state of each file in the cluster
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/files"
 *
 */
router.get('/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/files");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/files', 'arguments': {}};
    var filters = {'managers': 'alphanumeric_param', 'files': 'paths'}

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('managers' in req.query)
        data_request['arguments']['manager'] = filter.select_param_to_json(req.query.managers);
    if ('files' in req.query)
        data_request['arguments']['file_list'] = filter.select_param_to_json(req.query.files);

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/agents Get info about agents in cluster
 * @apiName GetClusteragentsInfo
 * @apiGroup Nodes
 *
 * @apiDescription Returns the state of each agent and the manager it's reporting to in the cluster
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/agents"
 *
 */
router.get('/agents', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/agents");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/agents', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /cluster/status Get info about cluster status
 * @apiName GetClusterstatus
 * @apiGroup Status
 *
 * @apiDescription Returns if the cluster is enabled or disabled
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/status"
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
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/config"
 *
 */
router.get('/config', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/config");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/config', 'arguments': {}};

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;
