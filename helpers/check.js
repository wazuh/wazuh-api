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

exports.configuration_file = function() {
    var config_fields = ['ossec_path', 'host', 'port', 'https', 'basic_auth', 'BehindProxyServer', 'logs', 'cors', 'cache_enabled', 'cache_debug', 'cache_time', 'log_path', 'ld_library_path', 'python'];

    for (i = 0; i < config_fields.length; i++) {

        // Exist
        if (!(config_fields[i] in config)){
            console.log("Configuration error: Element '" + config_fields[i] + "' not found. Exiting.");
            return -1;
        }

        if (config_fields[i] != "python"){
            // String
            if (typeof config[config_fields[i]] !== "string") {
                console.log("Configuration error: Element '" + config_fields[i] + "' must be an string. Exiting.");
                return -1;
            }
            // Empty
            if (!config[config_fields[i]].trim()){
                console.log("Configuration error: Element '" + config_fields[i] + "' is empty. Exiting.");
                return -1;
            }
        }
        else{
            // object
            if (typeof config.python !== "object") {
                console.log("Configuration error: Element '" + config_fields[i] + "' must be an array. Exiting.");
                return -1;
            }

            for (var j = 0; j < config.python.length; j++) {

                // Exist
                if (!("bin" in config.python[j]) || !("lib" in config.python[j])){
                    console.log("Configuration error: Element 'bin' or 'lib' not found. Exiting.");
                    return -1;
                }

                // String
                if (typeof config.python[j]["bin"] !== "string" || typeof config.python[j]["lib"] !== "string") {
                    console.log("Configuration error: Elements 'bin' and 'lib' must be an string. Exiting.");
                    return -1;
                }
                // Empty
                if (config.python[j]["bin"] != "python" && (!config.python[j]["bin"].trim() || !config.python[j]["lib"].trim())){
                    console.log("Configuration error: Element 'bin' or 'lib' empty. Exiting.");
                    return -1;
                }
            }
        }
    }

    return 0;
}


// Check Wazuh version
exports.wazuh = function(my_logger) {
    try {
        var fs = require("fs");
        var wazuh_version = 0;
        var version_regex = new RegExp('VERSION="v(.+)"');

        fs.readFileSync('/etc/ossec-init.conf').toString().split('\n').forEach(function (line) {
            var r = line.match(version_regex);
            if (r) {
                wazuh_version = parseFloat(r[1]);
                return;
            }
        });

        if (wazuh_version < 2) {
            if (wazuh_version == 0)
                var msg = "not";
            else
                var msg = wazuh_version;

            my_logger.log("Wazuh manager " + msg + " found. It is required Wazuh Manager 2.0 or newer. Exiting.");
            return -1;
        }
    } catch (e) {
        my_logger.log("WARNING: The installed version of Wazuh manager could not be determined. It is required Wazuh Manager 2.0 or newer.");
    }

    return 0;
}

exports.python = function(my_logger) {
    const execFileSync = require('child_process').execFileSync;

    var old_library_path = typeof process.env.LD_LIBRARY_PATH == 'undefined' ? '' : process.env.LD_LIBRARY_PATH;

    for (var i = 0; i < config.python.length; i++) {
        try {
            if (config.python[i].lib.length > 0)
                process.env.LD_LIBRARY_PATH = old_library_path + ":" + config.python[i].lib;

            var buffer = execFileSync(config.python[i].bin, ["-c", "import sys; print('.'.join([str(x) for x in sys.version_info[0:2]]))"]);
            var version = parseFloat(buffer.toString());

            if (version >= 2.7) {
                python_bin = config.python[i].bin;
                my_logger.debug("Selected Python binary at '" + python_bin + "'.");
                return 0;
            }
        } catch (e) {
        }

        process.env.LD_LIBRARY_PATH = old_library_path;
    }

    my_logger.log("No suitable Python version found. This application requires Python 2.7 or newer. Exiting.");
    return -1;
}
