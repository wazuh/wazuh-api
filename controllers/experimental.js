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

/**
 * @api {get} /experimental/syscollector/packages Get packages info of all agents
 * @apiName GetPackages
 * @apiGroup Packages
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [vendor] Filters by vendor.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [format] Filters by format.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns the agent's packages info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/packages?pretty&sort=-name&limit=2&offset=4"
 *
 */
router.get('/syscollector/packages', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/packages");

    var data_request = { 'function': '/experimental/syscollector/packages', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'vendor': 'alphanumeric_param', 'name': 'alphanumeric_param',
        'architecture': 'alphanumeric_param', 'format': 'alphanumeric_param'
    };


    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('vendor' in req.query)
        data_request['arguments']['filters']['vendor'] = req.query.vendor
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('format' in req.query)
        data_request['arguments']['filters']['format'] = req.query.format

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /experimental/syscollector/os Get os info of all agents
 * @apiName GetOS
 * @apiGroup OS
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [os_name] Filters by os_name.
 * @apiParam {String} [architecture] Filters by architecture.
 * @apiParam {String} [os_version] Filters by os_version.
 * @apiParam {String} [version] Filters by version.
 * @apiParam {String} [release] Filters by release.
 *
 * @apiDescription Returns the agent's os info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/os?pretty&sort=-os_name"
 *
 */
router.get('/syscollector/os', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/os");

    var data_request = { 'function': '/experimental/syscollector/os', 'arguments': {} };

    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'os_name': 'alphanumeric_param', 'architecture': 'alphanumeric_param',
        'os_version': 'alphanumeric_param', 'version': 'alphanumeric_param', 'release': 'alphanumeric_param'
    };


    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('architecture' in req.query)
        data_request['arguments']['filters']['architecture'] = req.query.architecture
    if ('os_name' in req.query)
        data_request['arguments']['filters']['os_name'] = req.query.os_name
    if ('os_version' in req.query)
        data_request['arguments']['filters']['os_version'] = req.query.os_version
    if ('version' in req.query)
        data_request['arguments']['filters']['version'] = req.query.version
    if ('release' in req.query)
        data_request['arguments']['filters']['release'] = req.query.release


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /experimental/syscollector/hardware Get hardware info of all agents
 * @apiName GetHardware
 * @apiGroup Hardware
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [ram_free] Filters by ram_free.
 * @apiParam {String} [ram_total] Filters by ram_total.
 * @apiParam {String} [cpu_cores] Filters by cpu_cores.
 * @apiParam {String} [cpu_mhz] Filters by cpu_mhz.
 * @apiParam {String} [cpu_name] Filters by cpu_name.
 * @apiParam {String} [board_serial] Filters by board_serial.
 *
 * @apiDescription Returns the agent's hardware info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/hardware?pretty&sort=-ram_free"
 *
 */
router.get('/syscollector/hardware', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/hardware");

    var data_request = { 'function': '/experimental/syscollector/hardware', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'ram_free': 'numbers', 'ram_total': 'numbers', 'cpu_cores': 'numbers', 'cpu_mhz': 'alphanumeric_param',
        'cpu_name': 'alphanumeric_param', 'board_serial': 'alphanumeric_param'
    };


    if (!filter.check(req.params, { 'agent_id': 'numbers' }, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('ram_free' in req.query)
        data_request['arguments']['filters']['ram_free'] = req.query.ram_free
    if ('ram_total' in req.query)
        data_request['arguments']['filters']['ram_total'] = req.query.ram_total
    if ('cpu_cores' in req.query)
        data_request['arguments']['filters']['cpu_cores'] = req.query.cpu_cores
    if ('cpu_mhz' in req.query)
        data_request['arguments']['filters']['cpu_mhz'] = req.query.cpu_mhz
    if ('cpu_name' in req.query)
        data_request['arguments']['filters']['cpu_name'] = req.query.cpu_name
    if ('board_serial' in req.query)
        data_request['arguments']['filters']['board_serial'] = req.query.board_serial


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /experimental/syscollector/processes Get processes info of all agents
 * @apiName GetProcesses
 * @apiGroup Processes
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {Number} [pid] Filters by process pid.
 * @apiParam {String} [egroup] Filters by process egroup.
 * @apiParam {String} [euser] Filters by process euser.
 * @apiParam {String} [fgroup] Filters by process fgroup.
 * @apiParam {Number} [nlwp] Filters by process nlwp.
 * @apiParam {Number} [pgrp] Filters by process pgrp.
 * @apiParam {Number} [priority] Filters by process priority.
 * @apiParam {String} [rgroup] Filters by process rgroup.
 * @apiParam {String} [ruser] Filters by process ruser.
 * @apiParam {String} [sgroup] Filters by process sgroup.
 * @apiParam {String} [suser] Filters by process suser.
 *
 * @apiDescription Returns the agent's processes info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/processes?pretty&limit=2&sort=priority"
 *
 */
router.get('/syscollector/processes', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/processes");

    var data_request = { 'function': '/experimental/syscollector/processes', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'pid': 'numbers', 'state': 'alphanumeric_param', 'ppid': 'numbers',
        'egroup': 'alphanumeric_param',
        'euser': 'alphanumeric_param', 'fgroup': 'alphanumeric_param',
        'name': 'alphanumeric_param', 'nlwp': 'numbers',
        'pgrp': 'numbers', 'priority': 'numbers',
        'rgroup': 'alphanumeric_param', 'ruser': 'alphanumeric_param',
        'sgroup': 'alphanumeric_param', 'suser': 'alphanumeric_param'
    };

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('pid' in req.query)
        data_request['arguments']['filters']['pid'] = req.query.pid;
    if ('egroup' in req.query)
        data_request['arguments']['filters']['egroup'] = req.query.egroup;
    if ('euser' in req.query)
        data_request['arguments']['filters']['euser'] = req.query.euser;
    if ('fgroup' in req.query)
        data_request['arguments']['filters']['fgroup'] = req.query.fgroup;
    if ('nlwp' in req.query)
        data_request['arguments']['filters']['nlwp'] = req.query.nlwp;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('pgrp' in req.query)
        data_request['arguments']['filters']['pgrp'] = req.query.pgrp;
    if ('priority' in req.query)
        data_request['arguments']['filters']['priority'] = req.query.priority;
    if ('rgroup' in req.query)
        data_request['arguments']['filters']['rgroup'] = req.query.rgroup;
    if ('ruser' in req.query)
        data_request['arguments']['filters']['ruser'] = req.query.ruser;
    if ('sgroup' in req.query)
        data_request['arguments']['filters']['sgroup'] = req.query.sgroup;
    if ('suser' in req.query)
        data_request['arguments']['filters']['suser'] = req.query.suser;


    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /experimental/syscollector/ports Get ports info of all agents
 * @apiName GetPorts
 * @apiGroup Ports
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {Number} [pid] Filters by pid.
 * @apiParam {String} [protocol] Filters by protocol.
 * @apiParam {String} [local_ip] Filters by local_ip.
 * @apiParam {Number} [local_port] Filters by local_port.
 * @apiParam {String} [remote_ip] Filters by remote_ip.
 * @apiParam {Number} [tx_queue] Filters by tx_queue.
 * @apiParam {String} [state] Filters by state.
 *
 * @apiDescription Returns the agent's ports info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/ports?pretty&limit=2&sort=protocol"
 *
 */
router.get('/syscollector/ports', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/ports");

    var data_request = { 'function': '/experimental/syscollector/ports', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'protocol': 'alphanumeric_param', 'local_ip': 'alphanumeric_param',
        'local_port': 'numbers', 'remote_ip': 'alphanumeric_param',
        'tx_queue': 'numbers', 'state': 'alphanumeric_param',
        'pid': 'numbers', 'process': 'alphanumeric_param'
    };

    if (!filter.check(req.query, filters, req, res))
        return;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('protocol' in req.query)
        data_request['arguments']['filters']['protocol'] = req.query.protocol;
    if ('local_ip' in req.query)
        data_request['arguments']['filters']['local_ip'] = req.query.local_ip;
    if ('local_port' in req.query)
        data_request['arguments']['filters']['local_port'] = req.query.local_port;
    if ('remote_ip' in req.query)
        data_request['arguments']['filters']['remote_ip'] = req.query.remote_ip;
    if ('remote_port' in req.query)
        data_request['arguments']['filters']['remote_port'] = req.query.remote_port;
    if ('tx_queue' in req.query)
        data_request['arguments']['filters']['tx_queue'] = req.query.tx_queue;
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('pid' in req.query)
        data_request['arguments']['filters']['pid'] = req.query.pid;
    if ('process' in req.query)
        data_request['arguments']['filters']['process'] = req.query.process;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /experimental/syscollector/netaddr Get network address info of all agents
 * @apiName GetNetaddr
 * @apiGroup Netaddr
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [proto] Filters by proto.
 * @apiParam {String} [address] Filters by address.
 * @apiParam {String} [broadcast] Filters by broadcast.
 * @apiParam {String} [netmask] Filters by netmask.
 *
 * @apiDescription Returns the agent's network address info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netaddr?pretty&limit=2&sort=proto"
 *
 */
router.get('/syscollector/netaddr', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/netaddr");

    var data_request = { 'function': '/experimental/syscollector/netaddr', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'proto': 'alphanumeric_param', 'address': 'alphanumeric_param',
        'broadcast': 'alphanumeric_param', 'netmask': 'alphanumeric_param',
        'id': 'numbers'
    };

    if (!filter.check(req.query, filters, req, res))
        return;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('proto' in req.query)
        data_request['arguments']['filters']['proto'] = req.query.proto;
    if ('address' in req.query)
        data_request['arguments']['filters']['address'] = req.query.address;
    if ('broadcast' in req.query)
        data_request['arguments']['filters']['broadcast'] = req.query.broadcast;
    if ('netmask' in req.query)
        data_request['arguments']['filters']['netmask'] = req.query.netmask;
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /experimental/syscollector/netproto Get network protocol info of all agents
 * @apiName GetNetproto
 * @apiGroup Netproto
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [iface] Filters by iface.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [gateway] Filters by gateway.
 * @apiParam {String} [dhcp] Filters by dhcp.
 *
 * @apiDescription Returns the agent's network protocol info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netproto?pretty&limit=2&sort=type"
 *
 */
router.get('/syscollector/netproto', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/netproto");

    var data_request = { 'function': '/experimental/syscollector/netproto', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'iface': 'alphanumeric_param', 'type': 'alphanumeric_param',
        'gateway': 'alphanumeric_param', 'dhcp': 'alphanumeric_param',
        'id': 'numbers'
    };

    if (!filter.check(req.query, filters, req, res))
        return;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('iface' in req.query)
        data_request['arguments']['filters']['iface'] = req.query.iface;
    if ('type' in req.query)
        data_request['arguments']['filters']['type'] = req.query.type;
    if ('gateway' in req.query)
        data_request['arguments']['filters']['gateway'] = req.query.gateway;
    if ('dhcp' in req.query)
        data_request['arguments']['filters']['dhcp'] = req.query.dhcp;
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /experimental/syscollector/netiface Get network interface info of all agents
 * @apiName GetNetiface
 * @apiGroup Netiface
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String} [id] Filters by id.
 * @apiParam {String} [name] Filters by name.
 * @apiParam {String} [adapter] Filters by adapter.
 * @apiParam {String} [type] Filters by type.
 * @apiParam {String} [state] Filters by state.
 * @apiParam {String} [mtu] Filters by mtu.
 * @apiParam {String} [tx_packets] Filters by tx_packets.
 * @apiParam {String} [rx_packets] Filters by rx_packets.
 * @apiParam {String} [tx_bytes] Filters by tx_bytes.
 * @apiParam {String} [rx_bytes] Filters by rx_bytes.
 * @apiParam {String} [tx_errors] Filters by tx_errors.
 * @apiParam {String} [rx_errors] Filters by rx_errors.
 * @apiParam {String} [tx_dropped] Filters by tx_dropped.
 * @apiParam {String} [rx_dropped] Filters by rx_dropped.
 *
 * @apiDescription Returns the agent's network interface info
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/experimental/syscollector/netiface?pretty&limit=2&sort=rx_bytes"
 *
 */
router.get('/syscollector/netiface', function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /experimental/syscollector/netiface");

    var data_request = { 'function': '/experimental/syscollector/netiface', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'sort': 'sort_param',
        'search': 'search_param', 'select': 'select_param',
        'id': 'numbers', 'name': 'alphanumeric_param',
        'adapter': 'alphanumeric_param', 'type': 'alphanumeric_param',
        'state': 'alphanumeric_param', 'mtu': 'numbers',
         'tx_packets': 'numbers', 'rx_packets': 'numbers', 'tx_bytes': 'numbers',
        'rx_bytes': 'numbers', 'tx_errors': 'numbers',
        'rx_errors': 'numbers', 'tx_dropped': 'numbers',
        'rx_dropped': 'numbers'
    };

    if (!filter.check(req.query, filters, req, res))
        return;
    data_request['arguments']['filters'] = {};

    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select)
    if ('offset' in req.query)
        data_request['arguments']['offset'] = req.query.offset;
    if ('limit' in req.query)
        data_request['arguments']['limit'] = req.query.limit;
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('id' in req.query)
        data_request['arguments']['filters']['id'] = req.query.id;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;
    if ('adapter' in req.query)
        data_request['arguments']['filters']['adapter'] = req.query.adapter;
    if ('type' in req.query)
        data_request['arguments']['filters']['type'] = req.query.type;
    if ('state' in req.query)
        data_request['arguments']['filters']['state'] = req.query.state;
    if ('mtu' in req.query)
        data_request['arguments']['filters']['mtu'] = req.query.mtu;
    if ('tx_packets' in req.query)
        data_request['arguments']['filters']['tx_packets'] = req.query.tx_packets;
    if ('rx_packets' in req.query)
        data_request['arguments']['filters']['rx_packets'] = req.query.rx_packets;
    if ('tx_bytes' in req.query)
        data_request['arguments']['filters']['tx_bytes'] = req.query.tx_bytes;
    if ('rx_bytes' in req.query)
        data_request['arguments']['filters']['rx_bytes'] = req.query.rx_bytes;
    if ('tx_errors' in req.query)
        data_request['arguments']['filters']['tx_errors'] = req.query.tx_errors;
    if ('rx_errors' in req.query)
        data_request['arguments']['filters']['rx_errors'] = req.query.rx_errors;
    if ('tx_dropped' in req.query)
        data_request['arguments']['filters']['tx_dropped'] = req.query.tx_dropped;
    if ('rx_dropped' in req.query)
        data_request['arguments']['filters']['rx_dropped'] = req.query.rx_dropped;

    execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });
})


module.exports = router;
