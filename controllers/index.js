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
apicache = require('apicache');
cache = apicache.middleware;
wazuh_control = api_path + "/models/wazuh-api.py";

var router = require('express').Router();
var users = require('../helpers/users');
var os = require("os");
var basic_auth = require('basic-auth');

// Cache options
if (config.cache_enabled.toLowerCase() == "yes") {
    if (config.cache_debug.toLowerCase() == "yes")
        cache_debug = true;
    else
        cache_debug = false;
    cache_opt = { debug: cache_debug, defaultDuration: parseInt(config.cache_time) };
}
else
    cache_opt = { enabled: false };

apicache.options(cache_opt);

// Content-type
router.post("*", function (req, res, next) {
    var content_type = req.get('Content-Type');

    if (!content_type || !(content_type == 'application/json' || content_type == 'application/x-www-form-urlencoded')){
        logger.debug(req.connection.remoteAddress + " POST " + req.path);
        res_h.bad_request(req, res, "607");
    }
    else
        next();
});

// All requests
router.all("*", function (req, res, next) {
    users.reset();
    var go_next = true;

    if (req.query) {
        // Pretty
        if ("pretty" in req.query) {
            req['pretty'] = true;
            delete req.query["pretty"];
        } else {
            req['pretty'] = false;
        }
    }

    var run_as_user = req.headers['es-security-runas-user'];
    var run_as_group = req.headers['es-security-runas-group'];

    var user = basic_auth(req);
    if (!user) { // token auth
        var token = req.headers['x-access-token'];
        users.authenticate_user_from_token(token, function (result, user_name) {
            if (!result) { // wrong token
                res_h.bad_request(req, res, "101");
                var log_msg = "[" + req.connection.remoteAddress + "] " + "Token: \"" + token + "\" - Authentication failed.";
                logger.log(log_msg);
            } else { // OK
                if (run_as_user || run_as_group) { // run_as? check run as privileges
                    users.has_user_run_as_privileges(user_name, function (err, privileges) {
                        if (!err && privileges) {
                            users.set_run_as_user(run_as_user);
                            users.set_run_as_group(run_as_group);
                            next();
                        } else {
                            res_h.bad_request(req, res, "401");
                            var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + user_name + "\" - Authentication failed: Unauthorized request. User has no privileges to use 'run as'.";
                            logger.log(log_msg);
                        }
                    });
                } else {
                    next();
                }
            }
        });
    } else { // user auth
        users.authenticate_user(user, function (result) {
            if (!result) { // wrong user or pass
                users.is_password_setted(user.name, function (result) { // first login?
                    if (result) { 
                        res_h.bad_request(req, res, "401");
                        var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + user.name + "\" - Authentication failed.";
                        logger.log(log_msg);
                    } else {
                        if ((req.originalUrl == '/api/user' || req.originalUrl == '/api/user?pretty') && req.method == "PUT" && "password" in req.body) { // PUT/api/user
                            users.set_run_as_user(user.name);
                            next();
                        } else { 
                            res_h.bad_request(req, res, "103");
                            var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + user.name + "\" - Authentication failed: Password not configured.";
                            logger.log(log_msg);
                        }
                    }
                });
            } else { // OK
                if (run_as_user || run_as_group) { // run_as? check run as privileges
                    users.has_user_run_as_privileges(user.name, function (err, privileges) {
                        if (!err && privileges) {
                            users.set_run_as_user(run_as_user);
                            users.set_run_as_group(run_as_group);
                            next();
                        } else {
                            res_h.bad_request(req, res, "401", "User has no privileges to use 'run as'.");
                            var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + user.name + "\" - Authentication failed: Unauthorized request. User has no privileges to use 'run as'.";
                            logger.log(log_msg);
                        }
                    });
                } else {
                    next();
                }
            }
        });
    }
});

// Controllers
router.use('/agents', require('./agents'));
router.use('/manager', require('./manager'));
router.use('/syscheck', require('./syscheck'));
router.use('/rootcheck', require('./rootcheck'));
router.use('/rules', require('./rules'));
router.use('/decoders', require('./decoders'));
router.use('/cache', require('./cache'));
router.use('/cluster', require('./cluster'));
router.use('/syscollector', require('./syscollector'));

if (config.basic_auth) {
    router.use('/api', require('./api'));
}

if (config.experimental_features) {
    router.use('/experimental', require('./experimental'));
}

// Index
router.get('/', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /");
    data = { 'msg': "Welcome to Wazuh HIDS API", 'api_version': "v" + info_package.version, 'hostname': os.hostname(), 'timestamp': new Date().toString() }
    json_res = { 'error': 0, 'data': data };
    res_h.send(req, res, json_res);
});

// Version
router.get('/version', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /version");

    json_res = { 'error': 0, 'data': "v" + info_package.version };

    res_h.send(req, res, json_res);
});

// ALWAYS Keep this as the last route
router.all('*', function (req, res) {
    logger.debug(req.connection.remoteAddress + " " + req.method + " " + req.path);
    json_res = { 'error': 603, 'message': errors.description(603) };
    res_h.send(req, res, json_res, 404);
});


// Router Errors
router.use(function (err, req, res, next) {
    logger.log("Internal Error");
    if (err.stack)
        logger.log(err.stack);
    logger.log("Exiting...");

    setTimeout(function () { process.exit(1); }, 500);
});



module.exports = router
