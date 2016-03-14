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
var router = express.Router();
var api_version = "v1.1.0";

// Access-Control-Allow
router.use(function(req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', config.AccessControlAllowOrigin);
    res.setHeader('Access-Control-Allow-Headers', config.AccessControlAllowHeaders);
    next();
});

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

/**
 * Versioning
 * Using: Header ("api-version") or url ("/v1", "/v1.0/")
 * ToDo: Directory Structure and specific routes
 */
router.use(function(req, res, next) {
    var api_version_header = req.get('api-version');
    var api_version_url = req.url.split('/')[1];
    var regex_version = /v\d+(?:\.\d+){0,1}/i;

    if (api_version_header)
        api_version = api_version_header;
    else if (api_version_url && regex_version.test(api_version_url))
        api_version = api_version_url;

    //console.log("Version: " + api_version);
    
    next();
});


// Controllers
router.use('/agents', require('./agents'));
router.use('/manager', require('./manager'));
router.use('/syscheck', require('./syscheck'));
router.use('/rootcheck', require('./rootcheck'));

// Index
router.get('/',function(req, res) {
    logger.log(req.host + " GET /");
    json_res = {'error': "0", 'response': "OSSEC-API", 'message': "wazuh.com"};
    res.json(json_res);
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 200");
});

// ALWAYS Keep this as the last route
router.all('*',function(req, res) {
    logger.log(req.connection.remoteAddress + " " + req.method + " " + req.path);
    json_res = { 'error': "603", 'response': null, 'message': errors.description(603)};
    res.status(404).json(json_res);
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 404");
});


// Router Errors
router.use(function(err, req, res, next){
    logger.log("Internal Error");
    if(err.stack)
        logger.log(err.stack);
    logger.log("Exiting...");
    
    process.exit(1);
});



module.exports = router
