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

var cron = require('node-cron');
var task = null;
var task_status = "disabled";


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
 * @api {get} /cluster/sync/status Get sync status
 * @apiName GetNodeKey
 * @apiGroup cluster
 *
 * @apiDescription Returns sync status
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X GET "https://127.0.0.1:55000/cluster/sync/status"
 *
 */
router.get('/sync/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/sync/status");

    if (task_status == "enabled"){
        json_res = {'error': 0, 'data': "Sync enabled"};
    }
    else{
        json_res = {'error': 0, 'data': "Sync disabled"};
    }
    res_h.send(req, res, json_res);

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

/**
 * @api {put} /cluster/sync/enable Enable syncrhonization
 * @apiName PutSync
 * @apiGroup cluster
 *
 * @apiDescription Enables sync
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X PUT "https://127.0.0.1:55000/cluster/sync/enable"
 *
 */
router.put('/sync/enable', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/sync/enable");

    if (req.user == "wazuh"){
        try {
            var valid = cron.validate(config.cluster.schedule);

            if (valid){
                task = cron.schedule(config.cluster.schedule, function() {
                  var data_request = {'function': 'PUT/cluster/sync', 'arguments': {}};
                  data_request['arguments']['output_file'] = "True";
                  execute.exec(python_bin, [wazuh_control], data_request, function (data) {});
                });

                task.start();
                task_status = "enabled";
                json_res = {'error': 0, 'data': "Sync enabled"};
            }
            else{
                json_res = {'error': 3, 'data': "Invalid config.cluster.schedule"};
            }
        }
        catch (e) {
            json_res = {'error': 3, 'data': "Internal error."};
        }

        res_h.send(req, res, json_res);
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})

/**
 * @api {put} /cluster/sync/disable Disable syncrhonization
 * @apiName PutSync
 * @apiGroup cluster
 *
 * @apiDescription Disables sync
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X PUT "https://127.0.0.1:55000/cluster/sync/disable"
 *
 */
router.put('/sync/disable', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/sync/disable");

    if (req.user == "wazuh"){
        if (task){
            task.stop();
        }
        json_res = {'error': 0, 'data': "Sync disabled"};
        task_status = "disabled";
        res_h.send(req, res, json_res);
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})

module.exports = router;
