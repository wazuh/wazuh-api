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



/**
 * @api {get} /api/user/authenticate Authenticate user
 * @apiName AuthenticateUser
 * @apiGroup Authentication
 *
 * @apiDescription Assigns and returns a token for the specified user. Also, returns information about user roles, and token.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user/authenticate?pretty"
 *
 */
router.get('/user/authenticate', function (req, res) {
    var user_name = basic_auth(req).name

    var token = auth.get_token(user_name);
    var data_request = { 'function': '/api/user/authenticate', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            var response = {
                data: {
                    token: token, username: user_name,
                    token_expires_in: config.token_expiration_time, roles: python_response.data.roles,
                    totalRoles: python_response.data.totalRoles
                }, error: 0
            };
            res_h.send(req, res, response, "200");
        } else {
            res_h.send(req, res, python_response);
        }
    });
});


/**
 * @api {put} /api/user Update current user
 * @apiName UpdateCurrentUser
 * @apiGroup Authentication
 *
 * @apiDescription Updates the current user information. Fields that can be updated: enabled.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT -H "Content-Type:application/json" -d '{"enabled":true}' "https://127.0.0.1:55000/api/user?pretty"
 *
 */
router.put('/user', function (req, res) {
    var user_name = basic_auth(req).name
    var data_request = { 'function': '/api/user', 'arguments': { 'only_verify_privileges': true } };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.body, { 'enabled': 'boolean' }, req, res))  // Filter with error
        return;

    var user_data = { enabled: req.body.enabled, name: user_name };

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            db_helper.update_user(user_data, function (result) {
                var response = {
                    data: {
                        user: user_data,
                        updated: result
                    }, error: 0
                };
                res_h.send(req, res, response);
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {get} /api/user Returns information about current user.
 * @apiName UpdateCurrentUser
 * @apiGroup Authentication
 *
 * @apiDescription Returns information about current user. Fields that returns: enabled.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user?pretty"
 *
 */
router.get('/user', function (req, res) {
    var user_name = basic_auth(req).name
    var data_request = { 'function': '/api/user', 'arguments': { 'only_verify_privileges': true } };
    data_request['url'] = req.originalUrl;

    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {
        if (python_response.error == 0 && python_response.data) {
            db_helper.get_user(user_name, function (result) {
                var response = {
                    data: {
                        user_name: result.name, 
                        enabled: !!parseInt(result.enabled)
                    }, error: 0
                };
                res_h.send(req, res, response);
            });
        } else {
            res_h.send(req, res, python_response);
        }
    });

});


/**
 * @api {get} /api/user/:user_name/privileges Returns the privileges of a specific user
 * @apiName GetUserPrivileges
 * @apiGroup Privileges
 *
 * @apiDescription Returns the privileges of a specific user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user/foo/privileges?pretty"
 *
 */
router.get('/user/:user_name/privileges', function (req, res) {
    var data_request = { 'function': '/api/user/:user_name/privileges', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    data_request['arguments']['user_name'] = req.params.user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /api/user/:user_name/roles Returns the roles of a specific user
 * @apiName GetUserRoles
 * @apiGroup Roles
 *
 * @apiDescription Returns the roles of a specific user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user/foo/roles?pretty"
 *
 */
router.get('/user/:user_name/roles', function (req, res) {
    var data_request = { 'function': '/api/user/:user_name/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    if (!filter.check(req.params, { 'user_name': 'names' }, req, res))  // Filter with error
        return;
    data_request['arguments']['user_name'] = req.params.user_name;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /api/user/roles Returns the roles of the current user
 * @apiName GetCurrentUserRoles
 * @apiGroup Roles
 *
 * @apiDescription Returns the roles of the current user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user/roles?pretty"
 *
 */
router.get('/user/roles', function (req, res) {
    var data_request = { 'function': '/api/user/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /api/user/privileges Returns the privileges of the current user
 * @apiName GetCurrentUserPrivileges
 * @apiGroup Privileges
 *
 * @apiDescription Returns the privileges of the current user.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/user/privileges?pretty"
 *
 */
router.get('/user/privileges', function (req, res) {
    var data_request = { 'function': '/api/user/privileges', 'arguments': {} };
    data_request['url'] = req.originalUrl;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
});


/**
 * @api {get} /api/roless Returns all roles
 * @apiName GetAllRoles
 * @apiGroup Roles
 *
 * @apiDescription Returns all existing roles in the API.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/api/roles?pretty"
 *
 */
router.get('/roles', function (req, res) {
    var data_request = { 'function': '/api/roles', 'arguments': {} };
    data_request['url'] = req.originalUrl;
    execute.exec(python_bin, [wazuh_control], data_request, function (python_response) {res_h.send(req, res, python_response)});
});


module.exports = router;
