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
var router = express.Router();
var api_version = "v1";

// Allow petitions from outside of the API URL
// ToDo: Review
router.use(function(req, res, next) {
    res.setHeader('Access-Control-Allow-Origin', '*');
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

// Index
router.get('/',function(req, res) {
    logger.log(req.host + " GET /");
    json_res = {'error': "0", 'response': "OSSEC-API'", 'message': "wazuh.com"};
    res.json(json_res);
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 200");
});

// ALWAYS Keep this as the last route
router.all('*',function(req, res) {
    logger.log(req.host + " GET " + JSON.stringify(req.params));
    json_res = { 'error': "603", 'response': null, 'message': errors.description(603)};
    res.status(404).json(json_res);
    logger.log("Response: " + JSON.stringify(json_res) + " HTTP Status: 404");
});

module.exports = router
