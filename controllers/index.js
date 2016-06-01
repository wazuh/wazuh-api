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

var express = require('express');
var errors = require('../helpers/errors');
var logger = require('../helpers/logger');
var config = require('../config.js');
var res_h = require('../helpers/response_handler');
var validator = require('../helpers/input_validation');

var router = express.Router();


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
    res_h.pretty = false;
    res_h.offset = 0;
    res_h.limit = 100;
    go_next = true;

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
                res_h.offset = req.query["offset"];
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
                res_h.limit = req.query["limit"];
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

// Index
router.get('/',function(req, res) {
    logger.log(req.connection.remoteAddress + " GET /");
    json_res = {'error': 0, 'data': "OSSEC-API", 'message': "wazuh.com"};
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
