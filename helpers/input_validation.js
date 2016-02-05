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
    var regex = /^\d+$/;
    return regex.test(n);
}

exports.names = function(name) {
    var regex = /^[a-zA-Z0-9\-\_\.]+$/;
    return regex.test(name);
}
