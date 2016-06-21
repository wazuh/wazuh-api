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

/********************************************/
/* GET
/********************************************/

// GET /agents - Get agents list
router.get('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents");
    var args = ["-f", "/agents"]

    var filters = [{'status':'alphanumeric_param'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                args = ["-f", "/agents", "-a", req.query.status]
                break;
        }
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /agents/total - Get number of agents
router.get('/total', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/total");
    var args = ["-f", "/agents/total"]

    var filters = [{'status':'alphanumeric_param'}];
    var check_filter = filter.check(req.query, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                args = ["-f", "/agents/total", "-a", req.query.status]
                break;
        }
    }

    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// GET /agents/:agent_id - Get Agent Info
router.get('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "/agents/:agent_id", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });

})

// GET /agents/:agent_id/key - Get Agent Key
router.get('/:agent_id/key', function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /agents/:agent_id/key");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "/agents/:agent_id/key", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


/********************************************/
/* PUT
/********************************************/

// PUT /agents/:agent_id/restart - Restart Agent
router.put('/:agent_id/restart', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_id/restart");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "PUT/agents/:agent_id/restart", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})

// PUT /agents/:agent_name - Add Agent
router.put('/:agent_name', function(req, res) {
    logger.log(req.connection.remoteAddress + " PUT /agents/:agent_name");

    var check_filter = filter.check(req.params, [{'agent_name':'names'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "PUT/agents/:agent_name", "-a", req.params.agent_name + "," + "any"]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


/********************************************/
/* DELETE
/********************************************/

// DELETE /agents/:agent_id - Remove Agent
router.delete('/:agent_id', function(req, res) {
    logger.log(req.connection.remoteAddress + " DELETE /agents/:agent_id");

    var check_filter = filter.check(req.params, [{'agent_id':'numbers'}], res);
    if (check_filter[0] < 0)  // Filter with error
        return;

    var args = ["-f", "DELETE/agents/:agent_id", "-a", req.params.agent_id]
    execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
})


/********************************************/
/* POST
/********************************************/

// POST /agents - Add Agent
router.post('/', function(req, res) {
    logger.log(req.connection.remoteAddress + " POST /agents");

    // If not IP set, we will use source IP.
    var ip = req.body.ip;
    if ( !ip ){
        // If we hare behind a proxy server, use headers.
        if (config.BehindProxyServer.toLowerCase() == "yes")
            ip = req.headers['x-forwarded-for'];
        else
            ip = req.connection.remoteAddress;

        // Extract IPv4 from IPv6 hybrid notation
        if (ip.indexOf("::ffff:") > -1) {
            var ipFiltered = ip.split(":");
            ip = ipFiltered[ipFiltered.length-1];
            logger.debug("Hybrid IPv6 IP filtered: " + ip);
        }
        logger.debug("Add agent with automatic IP: " + ip);
    }
    req.body.ip = ip;

    var filters = [{'name':'names', 'ip':'ips'}];
    var check_filter = filter.check(req.body, filters, res);
    if (check_filter[0] < 0)  // Filter with error
        return;
    else if (check_filter[0] == 1){ // Filter OK
        switch(check_filter[1]) {
            case 0:  // status
                var args = ["-f", "POST/agents", "-a", req.body.name + "," + req.body.ip]
                execute.exec(wazuh_control, args, function (data) { res_h.send(res, data); });
                break;
        }
    }
})



module.exports = router;
