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
                if (config.python[j]["bin"] != "python" && config.python[j]["bin"] != "python3" && (!config.python[j]["bin"].trim() || !config.python[j]["lib"].trim())){
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
        var wazuh_version_mayor = 0;
        var version_regex = new RegExp('VERSION="v(.+)"');
        var wazuh_version = "v0";

        fs.readFileSync('/etc/ossec-init.conf').toString().split('\n').forEach(function (line) {
            var match = line.match(version_regex);
            if (match) {
                wazuh_version = match[1]
                wazuh_version_mayor = parseInt(wazuh_version[0]);
                return;
            }
        });

        // Wazuh 2.0 or newer required
        if (wazuh_version_mayor < 2) {
            if (wazuh_version_mayor == 0)
                var msg = "not";
            else
                var msg = wazuh_version;

            var f_msg = "ERROR: Wazuh manager v" + msg + " found. It is required Wazuh manager v2.0.0 or newer. Exiting.";
            console.log(f_msg);
            my_logger.log(f_msg);
            return -1;
        }

        // Wazuh major.minor == API major.minor
        var wazuh_api_mm = info_package.version.substring(0, 3)
        if ( wazuh_version.substring(0, 3) != wazuh_api_mm ){
            var f_msg = "ERROR: Wazuh manager v" + wazuh_version + " found. Wazuh manager v" + wazuh_api_mm + ".x expected. Exiting.";
            console.log(f_msg);
            my_logger.log(f_msg);
            return -1;
        }
    } catch (e) {
        var f_msg = "WARNING: The installed version of Wazuh manager could not be determined. It is required Wazuh Manager 2.0 or newer.";
        console.log(f_msg);
        my_logger.log(f_msg);
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

    var f_msg = "ERROR: No suitable Python version found. This application requires Python 2.7 or newer. Exiting.";
    console.log(f_msg);
    my_logger.log(f_msg);
    return -1;
}
