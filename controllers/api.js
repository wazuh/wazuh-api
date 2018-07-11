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
var jwt = require('jsonwebtoken');
var auth = require('../helpers/auth');
var basic_auth = require('basic-auth');
var db_helper = require('../helpers/db');


router.get('/user/authenticate', function (req, res) {
    var user_name = basic_auth(req).name
    
    var token = auth.get_token(user_name);
    var data_request = { 'function': '/api/user/authenticate', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    
    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data){
            var response = { data: { token: token, username: user_name, 
                token_expires_in: config.token_expiration_time, roles:python_response.data.roles,
                totalRoles: python_response.data.totalRoles }, error: 0 };
            res_h.send(req, res, response, "200");
        } else {
            res_h.send(req, res, python_response);
        }
    });
});

router.get('/user/:user_name/privileges', function (req, res) {
    var data_request = { 'function': '/api/user/:user_name/privileges', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    data_request['arguments']['user_name'] = req.params.user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});

router.get('/user/:user_name/roles', function (req, res) {
    var data_request = { 'function': '/api/user/:user_name/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    data_request['arguments']['user_name'] = req.params.user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});




router.get('/roles', function (req, res) {
    var data_request = { 'function': '/api/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {res_h.send(req, res, python_response)});
});


module.exports = router;
