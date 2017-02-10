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

// Check Wazuh version

exports.wazuh = function() {
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

            logger.log("Wazuh manager " + msg + " found. It is required Wazuh Manager 2.0 or newer. Exiting.");
            return -1;
        }
    } catch (e) {
        logger.log("WARNING: The installed version of Wazuh manager could not be determined. It is required Wazuh Manager 2.0 or newer.");
    }

    return 0;
}

exports.python = function() {
    const execFileSync = require('child_process').execFileSync;

    switch (typeof config.python) {
    case "undefined":
        logger.error("No Python configuration found. Exiting.");
        return -1;
    case "object":
        break;
    default:
        logger.error("Invalid Python configuration. Exiting.");
        return -1;
    }

    var old_library_path = typeof process.env.LD_LIBRARY_PATH == 'undefined' ? '' : process.env.LD_LIBRARY_PATH;

    for (var i = 0; i < config.python.length; i++) {
        try {
            if (typeof config.python[i].bin === "undefined") {
                logger.error("Invalid Python configuration. Exiting.");
                return -1;
            }

            if (typeof config.python[i].lib !== "undefined" && config.python[i].lib.length > 0)
                process.env.LD_LIBRARY_PATH = old_library_path + ":" + config.python[i].lib;

            var buffer = execFileSync(config.python[i].bin, ["-c", "import sys; print('.'.join([str(x) for x in sys.version_info[0:2]]))"]);
            var version = parseFloat(buffer.toString());

            if (version >= 2.7) {
                python_bin = config.python[i].bin;
                logger.debug("Selected Python binary at '" + python_bin + "'.");
                return 0;
            }
        } catch (e) {
        }

        process.env.LD_LIBRARY_PATH = old_library_path;
    }

    logger.log("No suitable Python version found. This application requires Python 2.7 or newer. Exiting.");
    return -1;
}
