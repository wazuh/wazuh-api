/**
 * Wazuh API RESTful
 * Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
 * Wazuh.com
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

if (process.getuid() !== 0){
    console.log('A root user is required to start the API.');
    process.exit(1);
}

/********************************************/
/* Root actions
/********************************************/
try {
    var auth = require("http-auth");
} catch (e) {
    console.log("Dependencies not found. Try 'npm install' in /var/ossec/api. Exiting...");
    process.exit(1);
}

//  Get configuration
config = require('./configuration/config');

//  Get credentials
if (config.basic_auth.toLowerCase() == "yes"){
    var auth_secure = auth.basic({
        realm: "OSSEC API",
        file: __dirname + "/configuration/auth/user"
    });
}

//  Get Certs
var options;
if (config.https.toLowerCase() == "yes"){
    var fs = require('fs');
    options = {
      key: fs.readFileSync(__dirname + '/configuration/ssl/server.key'),
      cert: fs.readFileSync(__dirname + '/configuration/ssl/server.crt')
    };
}

/********************************************/
/* Drop privileges
/********************************************/
try {
    process.setgid('ossec');
    process.setuid('ossec');
} catch(err) {
    console.log('Drop privileges failed: ' + err.message);
    process.exit(1);
}

/********************************************/
/* Modules, vars and global vars
/********************************************/
try {
    var express = require('express');
    var bodyParser = require('body-parser');
    var cors = require('cors')
    var moment = require('moment');
} catch (e) {
    console.log("Dependencies not found. Try 'npm install' in /var/ossec/api. Exiting...");
    process.exit(1);
}

logger = require('./helpers/logger');
res_h = require('./helpers/response_handler');
api_path = __dirname;
python_bin = '';

/********************************************/
/* Config APP
/********************************************/
current_version = "v2.0.0";

if (process.argv.length == 3 && process.argv[2] == "-f")
    logger.set_foreground();

// Check Wazuh and Python version
const check = require('./helpers/check');

if (check.wazuh() < 0 || check.python() < 0) {
    setTimeout(function(){ process.exit(1); }, 500);
    return;
}

var port = process.env.PORT || config.port;

if (config.host != "0.0.0.0")
    var host = config.host;

var app = express();

// CORS
if (config.cors.toLowerCase() == "yes"){
    app.use(cors());
}

// Basic authentication
if (config.basic_auth.toLowerCase() == "yes"){
    app.use(auth.connect(auth_secure));
}

auth_secure.on('fail', (result, req) => {
    var log_msg = "[" + req.connection.remoteAddress + "] " + "User: \"" + result.user + "\" - Authentication failed.";
    logger.log(log_msg);
});

auth_secure.on('error', (error, req) => {
    var log_msg = "[" + req.connection.remoteAddress + "] Authentication error: " + error.code + " - " + error.message;
    logger.log(log_msg);
});

// Body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

/**
 * Versioning
 * Using: Header: "api-version: vX.Y" or URL: /v2.0.0/
 */
app.use(function(req, res, next) {
    var api_version_header = req.get('api-version');
    var api_version_url = req.path.split('/')[1];
    var regex_version = /^v\d+(?:\.\d+){0,2}$/i;
    var new_url = "";

    if (api_version_url && regex_version.test(api_version_url))
        new_url = req.url;
    else if (api_version_header && regex_version.test(api_version_header))
        new_url = "/" + api_version_header + req.url;
    else
        new_url = "/" + current_version + req.url;

    req.url = new_url;

    next();
});


// Controllers
app.use("/" + current_version, require('./controllers'));


// APP Errors
app.use (function (err, req, res, next){

    if ( err == "Error: invalid json" ){
        logger.debug(req.connection.remoteAddress + " " + req.method + " " + req.path);
        res_h.bad_request(req, res, "607");
    }
    else if ('status' in err && err.status == 400){
        var msg = "";
        if ('body' in err)
            msg = "Body: " + err.body;
        res_h.bad_request(req, res, "614", msg);
    }
    else{
        logger.log("Internal Error");
        if(err.stack)
            logger.log(err.stack);
        logger.log("Exiting...");
        setTimeout(function(){ process.exit(1); }, 500);
    }
});

/********************************************/
/* Create server
/********************************************/
if (config.https.toLowerCase() == "yes"){
    var https = require('https');
    var server = https.createServer(options, app).listen(port, host, function(){
        logger.log("Listening on: https://" + server.address().address + ":" + port);
    });
}
else{
    var http = require('http');
    var server = http.createServer(app).listen(port, host, function(){
        logger.log("Listening on: http://" + server.address().address + ":" + port);
    });
}

/********************************************/
/* Event handler
/********************************************/
process.on('uncaughtException', function(err) {

    if (err.errno == "EADDRINUSE")
        logger.log("Error: Address in use (port " + port + "): Close the program using that port or change the port.")
    else {
      logger.log("Internal Error: uncaughtException");
      if(err.stack)
          logger.log(err.stack);
    }

    logger.log("Exiting...");
    setTimeout(function(){ process.exit(1); }, 500);
});

process.on('SIGTERM', function() {
    logger.log("Exiting... (SIGTERM)");
    setTimeout(function(){ process.exit(1); }, 500);
});

process.on('SIGINT', function() {
    logger.log("Exiting... (SIGINT)");
    setTimeout(function(){ process.exit(1); }, 500);
});
