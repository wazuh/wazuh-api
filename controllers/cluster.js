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

var cron       = require('node-cron');
var fileSystem = require('fs');
var config     = require('../configuration/config.js')

var task = null;


/**
 * @api {get} /cluster/nodes Get nodes list
 * @apiName GetNodeList
 * @apiGroup Nodes
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
 * @apiName GetNodeInfo
 * @apiGroup Nodes
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
 * @api {get} /cluster/node/token Get node token
 * @apiName GetNodetoken
 * @apiGroup Nodes
 *
 * @apiDescription Returns the Node token
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X GET "https://127.0.0.1:55000/cluster/node/token"
 *
 */
router.get('/node/token', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node/token");

    if (req.user == "wazuh"){
        req.apicacheGroup = "cluster";

        var data_request = {'function': '/cluster/node/token', 'arguments': {}};
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})


/**
 * @api {get} /cluster/sync/status Get sync status
 * @apiName GetNodeKey
 * @apiGroup Synchronization
 *
 * @apiDescription Returns sync status
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X GET "https://127.0.0.1:55000/cluster/sync/status"
 *
 */
router.get('/sync/status', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/sync/status");

    try {
        status = fileSystem.readFileSync(config.ossec_path + '/stats/.cluster_status');
        json_res = {'error': 0, 'data': "Sync " + (status == 1 ? "enabled" : "disabled")};
    } catch (e) {
        if (e.code === 'ENOENT') json_res = {'error': 0, 'data': "Sync disabled"};
        else json_res = {'error': 3, 'data': "Internal error: " + e.toString()};
    }


    res_h.send(req, res, json_res);

})


/**
 * @api {put} /cluster/sync Sync files
 * @apiName GetSync
 * @apiGroup Synchronization
 *
 * @apiDescription Sync files
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X PUT "https://127.0.0.1:55000/cluster/sync"
 *
 */
router.put('/sync', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/sync");

    if (req.user == "wazuh"){
        req.apicacheGroup = "cluster";

        debug = 'debug' in req.query ? true : false;

        var data_request = {'function': 'PUT/cluster/sync', 'arguments': {'debug': debug}};
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})

/**
 * @api {put} /cluster/sync/force Sync files (force)
 * @apiName GetSyncForce
 * @apiGroup Synchronization
 *
 * @apiDescription Sync files (force)
 *
 * @apiExample {curl} Example usage:
 *     curl -u wazuh:wazuh -k -X PUT "https://127.0.0.1:55000/cluster/sync/force"
 *
 */
router.put('/sync/force', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /cluster/sync/force");

    if (req.user == "wazuh"){
        req.apicacheGroup = "cluster";

        debug = 'debug' in req.query ? true : false;

        var data_request = {'function': 'PUT/cluster/sync', 'arguments': {'debug': debug}};
        data_request['arguments']['force'] = "True";
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})


/**
 * @api {put} /cluster/sync/enable Enable synchronization
 * @apiName PutSyncEnable
 * @apiGroup Synchronization
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

                fileSystem.writeFileSync(config.ossec_path + '/stats/.cluster_status', '1');

                json_res = {'error': 0, 'data': "Sync enabled"};
            }
            else{
                json_res = {'error': 3, 'data': "Invalid config.cluster.schedule"};
            }
        }
        catch (e) {
            json_res = {'error': 3, 'data': "Internal error: " + e.toString()};
        }

        res_h.send(req, res, json_res);
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }

})

/**
 * @api {put} /cluster/sync/disable Disable synchronization
 * @apiName PutSyncDisable
 * @apiGroup Synchronization
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

        try {
            fileSystem.writeFileSync(config.ossec_path + '/stats/.cluster_status', '0');
        } catch (e) {
            json_res = {'error': 3, 'data': "Internal error: " + e.toString()};
        }

        res_h.send(req, res, json_res);
    }
    else {
        res_h.unauthorized_request(req, res, 100, "User: " + req.user);
    }
})

/**
 * @api {get} /cluster/node/zip Download a list of files in zip format
 * @apiName GetZipFile
 * @apiGroup Zip
 *
 * @apiParam {list} list_path List of files to include in zip file
 *
 * @apiDescription Returns a zip file with requested files in list_path
 * 
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X POST -H "Content-Type:application/json" -d '{"list_path":["/tmp/test/1.txt"], "node_orig": "mynode"}' "http://127.0.0.1:55000/cluster/node/zip"
 *
**/
router.post('/node/zip', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node/files/zip");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/cluster/node/files/zip', 'arguments': {}};
    var filters = {'node_orig': 'alphanumeric_param', 'list_path': 'alphanumeric_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('node_orig' in req.body)
        data_request['arguments']['node_orig'] = req.body.node_orig;
    if ('list_path' in req.body)
        data_request['arguments']['list_path'] = req.body.list_path;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send_file(req, res, data, 'zip'); });
})

/**
 * @api {get} /cluster/node/files Check files status
 * @apiName GetManagerFile
 * @apiGroup Info
 *
 * @apiParam {string} file_name File Name
 *
 * @apiDescription Returns the file content
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/node/files
 *
 */
router.get('/node/files', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/node/files");

    req.apicacheGroup = "manager";

    var data_request = {'function': '/cluster/node/files', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param', 'search':'search_param', 'status':'alphanumeric_param', 'download':'search_param','path':'paths', 'file':'alphanumeric_param', 'orig_node':'alphanumeric_param'};

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
    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;
    if ('path' in req.query)
        data_request['arguments']['path'] = req.query.path;
    if ('file' in req.query)
        data_request['arguments']['file'] = req.query.file;

    if ('download' in req.query)
        res_h.send_file(req, res, req.query.download, 'files');
    else
        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})



module.exports = router;
