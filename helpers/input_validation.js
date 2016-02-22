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

exports.numbers = function(n) {
    if (typeof n != 'undefined'){
        var regex = /^\d+$/;
        return regex.test(n);
    }
    else
        return false;
}

exports.names = function(name) {
    if (typeof name != 'undefined'){
        var regex = /^[a-zA-Z0-9\-\_\.\\\/]+$/;
        return regex.test(name);
    }
    else
        return false;
}

exports.dates = function(date) {
    if (typeof date != 'undefined'){
        var regex = /^\d{8}$/;
        return regex.test(date);
    }
    else
        return false;
}

exports.ips = function(ip) {
    if (typeof ip != 'undefined'){
        var regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d{1,2})*$|any$|ANY$/;
        return regex.test(ip);
    }
    else
        return false;
}
