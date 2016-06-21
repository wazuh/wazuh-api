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


errors = require('../helpers/errors');
filter = require('../helpers/filters');
execute = require('../helpers/execute');
wazuh_control = config.api_path + "/models/wazuh-control.py";

var router = require('express').Router();
var validator = require('../helpers/input_validation');

// Content-type
router.post("*", function(req, res, next) {
    var content_type = req.get('Content-Type');

    if (!content_type || !(content_type == 'application/json' || content_type == 'application/x-www-form-urlencoded')){
        logger.log(req.connection.remoteAddress + " POST " + req.path);
        res_h.bad_request("607", "", res);
    }
    else
        next();
});

// All requests
router.all("*", function(req, res, next) {
    var go_next = true;
    res_h.pretty = false;
    execute.query_offset = 0;
    execute.query_limit = 0;

    if (req.query){
        // Pretty
        if ("pretty" in req.query){
            res_h.pretty = true;
            delete req.query["pretty"];
        }

        // Pagination - offset
        if ("offset" in req.query){
            if (!validator.numbers(req.query["offset"])){
                res_h.bad_request("600", "Field: offset", res);
                go_next = false;
            }else{
                execute.query_offset = req.query["offset"];
                delete req.query["offset"];
            }
        }

        // Pagination - limit
        if ("limit" in req.query){
            if (!validator.numbers(req.query["limit"])){
                res_h.bad_request("600", "Field: limit", res);
                go_next = false;
            }
            else{
                execute.query_limit = req.query["limit"];
                delete req.query["limit"];
            }
        }
    }

    if (go_next)
        next();
});

// Controllers
router.use('/agents', require('./agents'));
router.use('/manager', require('./manager'));
router.use('/syscheck', require('./syscheck'));
router.use('/rootcheck', require('./rootcheck'));
router.use('/rules', require('./rules'));
router.use('/decoders', require('./decoders'));

// Index
router.get('/',function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /");
    json_res = {'error': 0, 'data': "OSSEC-API", 'message': "wazuh.com"};
    res_h.send(res, json_res);
});

// Version
router.get('/version',function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /version");
    json_res = {'error': 0, 'data': current_version, 'message': ""};
    res_h.send(res, json_res);
});

// ALWAYS Keep this as the last route
router.all('*',function(req, res) {
    logger.log(req.connection.remoteAddress + " " + req.method + " " + req.path);
    json_res = { 'error': 603, 'data': "", 'message': errors.description(603)};
    res_h.send(res, json_res, 404);
});


// Router Errors
router.use(function(err, req, res, next){
    logger.log("Internal Error");
    if(err.stack)
        logger.log(err.stack);
    logger.log("Exiting...");

    setTimeout(function(){ process.exit(1); }, 500);
});



module.exports = router
