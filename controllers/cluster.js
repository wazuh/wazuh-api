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
 * @api {get} /cluster/sync Get pending files
 * @apiName GetSync
 * @apiGroup cluster
 *
 * @apiDescription Returns files pending to by sync
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/cluster/sync"
 *
 */
router.get('/sync', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /cluster/sync");

    req.apicacheGroup = "cluster";

    var data_request = {'function': '/cluster/sync', 'arguments': {}};
    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {post} /nodes Add Node
 * @apiName PostAddNode
 * @apiGroup Cluster
 *
 * @apiParam {String} name Agent name.
 *
 * @apiDescription Add a new node
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X POST -d '{"node":"node1","ip":"https://172.0.0.16","user":"foo","password":"bar"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/nodes?pretty"
 *
 */
router.post('/nodes', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /nodes");

    var data_request = {'function': 'POST/cluster/nodes', 'arguments': {}};

    if ('node' in req.body && 'user' in req.body && 'password' in req.body && 'ip' in req.body){

      data_request['arguments']['ip'] = req.body.ip;
      data_request['arguments']['user'] = req.body.user;
      data_request['arguments']['password'] = req.body.password;
      data_request['arguments']['node'] = req.body.node;

        execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
    }else
        res_h.bad_request(req, res, 604, "Missing field: 'node', 'ip', 'user' or 'password'");
})



module.exports = router;
