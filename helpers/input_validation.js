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
        var regex = /^[a-zA-Z0-9_\-\.]+$/;
        return regex.test(name);
    }
    else
        return false;
}

exports.paths = function(path) {
    if (typeof path != 'undefined'){
        var regex = /^[a-zA-Z0-9\-\_\.\\\/:]+$/;
        return regex.test(path);
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
        var regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2])){0,1}$|^any$|^ANY$/;
        return regex.test(ip);
    }
    else
        return false;
}

exports.alphanumeric_param = function(param) {
    if (typeof param != 'undefined'){
        var regex = /^[a-zA-Z0-9_\-\.\+\s]+$/;
        return regex.test(param);
    }
    else
        return false;
}

exports.sort_param = function(param) {
    if (typeof param != 'undefined'){
        var regex = /^[a-zA-Z0-9_\-\,\s\+]+$/; // + is translated as \s
        return regex.test(param);
    }
    else
        return false;
}

exports.search_param = function(param) {
    if (typeof param != 'undefined'){
        var regex = /^[a-zA-Z0-9\s_\-/\\:\.\"\'@~\+]+$/;
        return regex.test(param);
    }
    else
        return false;
}

exports.ranges = function(range) {
    if (typeof range != 'undefined'){
        var regex = /^[0-9]+$|^[0-9]{1,2}\-[0-9]{1,2}$/;
        return regex.test(range);
    }
    else
        return false;
}

exports.hashes = function(hash) {
    if (typeof hash != 'undefined'){
        var regex = /^[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?$/;  // md5 or sha1
        return regex.test(hash);
    }
    else
        return false;
}
