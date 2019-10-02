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

var should = require('should');
var assert = require('assert');
var request = require('supertest');
var common = require('./common.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Summary', function() {

    describe('GET/summary/agents', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/summary/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err)

                res.body.should.have.properties(['error', 'data'])

                res.body.error.should.equal(0)
                res.body.data.should.have.properties(['nodes', 'groups', 'agent_os',
                                                      'agent_version', 'agent_status',
                                                      'last_registered_agent'])
                // nodes
                res.body.data.nodes.should.have.properties(['items', 'totalItems'])
                res.body.data.nodes.should.be.an.integer
                res.body.data.nodes.items[0].should.have.properties(['count', 'node_name'])
                res.body.data.nodes.items[0].count.should.be.an.integer
                res.body.data.nodes.items[0].node_name.should.be.equal('master')
                res.body.data.nodes.items[1].should.have.properties(['count', 'node_name'])
                res.body.data.nodes.items[1].count.should.be.an.integer
                res.body.data.nodes.items[1].node_name.should.be.equal('worker-1')
                res.body.data.nodes.items[2].should.have.properties(['count', 'node_name'])
                res.body.data.nodes.items[2].count.should.be.an.integer
                res.body.data.nodes.items[2].node_name.should.be.equal('worker-2')
                // groups
                res.body.data.groups.should.have.properties(['items', 'totalItems'])
                res.body.data.groups.should.be.an.integer
                res.body.data.groups.items[0].should.have.properties(['count', 'name', 'mergedSum', 'configSum'])
                // agent_os
                res.body.data.agent_os.should.have.properties(['items', 'totalItems'])
                res.body.data.agent_os.should.be.an.integer
                res.body.data.agent_os.items[0].should.have.properties(['os', 'count'])
                res.body.data.agent_os.items[0].os.should.have.properties(['name', 'platform', 'version'])
                res.body.data.agent_os.items[0].count.should.be.an.integer
                // agent_version
                res.body.data.agent_version.should.have.properties(['items', 'totalItems'])
                res.body.data.agent_version.should.be.an.integer
                res.body.data.agent_version.items[0].should.have.properties(['count', 'version'])
                res.body.data.agent_version.items[0].count.should.be.an.integer
                res.body.data.agent_version.items[0].version.should.be.String
                // agent_status
                res.body.data.agent_status.should.have.properties(['Total', 'Active', 'Disconnected', 'Never connected', 'Pending'])
                res.body.data.agent_status['Active'].should.be.above(0)
                res.body.data.agent_status['Total'].should.be.above(0)
                res.body.data.agent_status['Disconnected'].should.be.an.integer
                res.body.data.agent_status['Never connected'].should.be.an.integer
                res.body.data.agent_status['Pending'].should.be.an.integer
                // last_registered_agent
                res.body.data.last_registered_agent.should.have.properties(['os', 'ip', 'node_name', 'name', 'dateAdd',
                                                                           'id', 'manager', 'mergedSum', 'lastKeepAlive',
                                                                           'group', 'version', 'configSum', 'status',
                                                                           'registerIP'])
                res.body.data.last_registered_agent.os.should.have.properties(['arch', 'major', 'name', 'platform', 'uname', 'version'])
                res.body.data.last_registered_agent.group.should.be.an.Array

                done()

            });
        });

    });  // GET/agents/full_summary

});  // Summary

