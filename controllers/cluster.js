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
 * @api {get} /cluster/nodes Get nodes list
 * @apiName GetNodeList
 * @apiGroup cluster
 *
 * @apiDescription Returns the Nodes list
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
 * @api {get} /cluster/node Get node info
 * @apiName GetNodeList
 * @apiGroup cluster
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
 * @api {get} /cluster/node/key Get node key
 * @apiName GetNodeKey
 * @apiGroup cluster
 *
 * @apiDescription Returns the Node key
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X GET "https://127.0.0.1:55000/cluster/node/key"
 *
 */
router.get('/node/key', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node/key");

    if (req.user == "wazuh"){
        req.apicacheGroup = "cluster";

        var data_request = {'function': '/cluster/node/key', 'arguments': {}};
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})

/**
 * @api {put} /cluster/sync Get pending files
 * @apiName GetSync
 * @apiGroup cluster
 *
 * @apiDescription Returns files pending to by sync
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X PUT "https://127.0.0.1:55000/cluster/sync"
 *
 */
router.put('/sync', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/sync");

    if (req.user == "wazuh"){
        req.apicacheGroup = "cluster";

        var data_request = {'function': 'PUT/cluster/sync', 'arguments': {}};
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})


module.exports = router;
