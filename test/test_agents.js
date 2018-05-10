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

var should  = require('should');
var assert  = require('assert');
var request = require('supertest');
var fs      = require('fs');
var common  = require('./common.js');


process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

var disconnected_agent_properties = ['status', 'ip', 'id', 'name', 'dateAdd'];
var manager_properties = disconnected_agent_properties.concat(['version', 'manager_host', 'lastKeepAlive', 'os']);
var agent_properties = manager_properties.concat(['configSum', 'mergedSum', 'group']);
var agent_os_properties = ['major', 'name', 'uname', 'platform', 'version', 'codename', 'arch'];

describe('Agents', function() {

    describe('GET/agents', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)

                res.body.data.items[0].should.have.properties(manager_properties);
                res.body.data.items[1].should.have.properties(agent_properties);
                res.body.data.items[0].os.should.have.properties(agent_os_properties);
                res.body.data.items[1].os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/agents?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(manager_properties);
                res.body.data.items[0].id.should.have.equal('000');
                res.body.data.items[0].status.should.have.equal('Active');
                done();
            });
        });

        it('Sort', function(done) {
            request(common.url)
            .get("/agents?sort=-id")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].id.should.equal('001');
                res.body.data.items[0].should.have.properties(agent_properties);
                done();
            });
        });

        it('Wrong Sort', function(done) {
            request(common.url)
            .get("/agents?sort=-wrongParameter")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1403);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/agents?search=001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].id.should.be.equal("001");
                res.body.data.items[0].should.have.properties(agent_properties);
                res.body.data.items[0].os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Selector', function(done) {
            request(common.url)
            .get("/agents?select=date_add,merged_sum")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['dateAdd', 'id']);
                res.body.data.items[1].should.have.properties(['dateAdd', 'mergedSum', 'id']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents?select=wrongParam")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });

        var expected_version = 0;
        before(function(done) {
            request(common.url)
            .get("/version")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
              expected_version="Wazuh "+String(res.body.data);
              done();
            });
        });

        it('Version', function(done) {
            request(common.url)
            .get("/agents?version="+expected_version.replace(/\s/g, ''))
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['version']);
                res.body.data.items[0].version.should.be.equal(expected_version);
                done();
            });
        });


        var expected_os_platform = "";
        var expected_os_version = "";
        var expected_manager_host = "";
        before(function(done) {
            request(common.url)
            .get("/agents")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                expected_os_platform = res.body.data.items[0].os.platform;
                expected_os_version = res.body.data.items[0].os.version;
                expected_manager_host = res.body.data.items[0].manager_host;
                done();
            });
        });

        it('Os.platform', function(done) {
            request(common.url)
            .get("/agents?os.platform=" + expected_os_platform)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['platform']);
                res.body.data.items[0].os.platform.should.be.equal(expected_os_platform);
                done();
            });
        });

        it('Os.version', function(done) {
            request(common.url)
            .get("/agents?os.version=" + expected_os_version)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['version']);
                res.body.data.items[0].os.version.should.be.equal(expected_os_version);
                done();
            });
        });

        it('ManagerHost', function(done) {
            request(common.url)
            .get("/agents?manager=" + expected_manager_host)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].os.should.have.properties(['version']);
                res.body.data.items[0].manager_host.should.be.equal(expected_manager_host);
                done();
            });
        });

        it('Filters: status', function(done) {
            request(common.url)
            .get("/agents?status=aCtIvE")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['status', 'ip', 'id', 'name']);
                done();
            });
        });

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/agents?random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

        it('Filters: Invalid filter - Extra field', function(done) {
            request(common.url)
            .get("/agents?status=aCtIvE&random")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(604);
                done();
            });
        });

    });  // GET/agents

    describe('GET/agents/summary', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/summary")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['Active', 'Total', 'Disconnected', 'Never connected']);
                res.body.data['Active'].should.be.above(0);
                res.body.data['Total'].should.be.an.integer;
                res.body.data['Disconnected'].should.be.an.integer;
                res.body.data['Never connected'].should.be.an.integer;
                done();
            });
        });

    });  // GET/agents/summary

    describe('GET/agents/summary/os', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/summary/os")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.be.instanceof(String)
                done();
            });
        });

    });  // GET/agents/summary/os

    describe('GET/agents/:agent_id', function() {

        it('Request (manager)', function(done) {
            request(common.url)
            .get("/agents/000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.id.should.equal("000");
                res.body.data.should.have.properties(manager_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Request (agent)', function(done) {
            request(common.url)
            .get("/agents/001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.id.should.equal("001");
                res.body.data.should.have.properties(agent_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });



        it('Selector', function(done) {
            request(common.url)
            .get("/agents/001?select=date_add,merged_sum")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.have.properties(['dateAdd', 'mergedSum']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents/001?select=wrongParam")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Errors: No agent', function(done) {
            request(common.url)
            .get("/agents/9999999")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });
    });  // GET/agents/:agent_id

    describe('GET/agents/name/:agent_name', function() {
        var expected_name = ""
        before(function(done) {
            request(common.url)
            .get("/agents/001")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.data.should.have.properties(agent_properties);
                res.body.error.should.equal(0);
                expected_name = res.body.data.name;
                done();
            });
        });
        it('Request', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name)
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(agent_properties);
                res.body.data.os.should.have.properties(agent_os_properties);
                done();
            });
        });

        it('Wrong name', function(done) {
            request(common.url)
            .get("/agents/name/non_existent_agent")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });

        it('Selector', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name+"?select=date_add,merged_sum,os_name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.an.Object;
                res.body.data.should.have.properties(['mergedSum','dateAdd','os']);
                res.body.data.os.should.have.properties(['name']);
                done();
            });
        });

        it('Not allowed selector', function(done) {
            request(common.url)
            .get("/agents/name/"+expected_name+"?select=wrongField")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1724);
                done();
            });
        });
    });  // GET/agents/name/:agent_name

    describe('GET/agents/:agent_id/key', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/001/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/agents/abc/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Errors: No key', function(done) {
            request(common.url)
            .get("/agents/999999/key")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });
    });  // GET/agents/:agent_id/key

    describe('PUT/agents/:agent_id/group/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .put("/agents/001/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad agent name', function(done) {
            request(common.url)
            .put("/agents/001!/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Params: Agent does not exist', function(done) {
            request(common.url)
            .put("/agents/1568/group/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1701);
                done();
            });
        });

    });  // PUT/agents/:agent_id/group/:group_id

    describe('PUT/agents/groups/:group_id', function() {

        after(function(done) {
            request(common.url)
            .delete("/agents/groups/newgroupcreated")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err, res) {
                if (err) return done(err);
                done();
              });
        });

        it('Request', function(done) {

            request(common.url)
            .put("/agents/groups/newgroupcreated")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .put("/agents/groups/!group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

        it('Params: Group already exists', function(done) {
            request(common.url)
            .put("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1711);
                done();
            });
        });

    });  // PUT/agents/groups/:group_id

    describe('GET/agents/groups', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/agents/groups")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.an.array;
                res.body.data.items[0].should.have.properties(['count','conf_sum','merged_sum','name']);
                res.body.data.items[1].name.should.equal("webserver");
                res.body.data.items[1].count.should.equal(1);

                done();
            });
        });

    });  // GET/agents/groups

    describe('GET/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/web!-ña")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // GET/agents/groups/:group_id

    describe('GET/agents/groups/:group_id/configuration', function() {

        before(function(done) {
            // write a configuration example
            var agent_conf_example = "\
            <agent_config name=\"agent_name\">\
                <localfile>\
                    <location>/var/log/my.log</location>\
                    <log_format>syslog</log_format>\
                </localfile>\
            </agent_config>\
            ";
            var config_path = common.ossec_path+'/etc/shared/webserver/agent.conf';
            fs.writeFile(config_path, agent_conf_example, (err) => {
                if (err) return done(err);
                done();
            });
        });

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['totalItems', 'items']);
                res.body.error.should.equal(0);
                res.body.data.items[0].should.have.properties(['config','filters']);
                res.body.data.items[0].config.should.have.properties(['localfile']);
                res.body.data.items[0].filters.should.have.properties(['name']);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/configuration")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // GET/agents/groups/:group_id/configuration

    describe('GET/agents/groups/:group_id/files', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // GET/agents/groups/:group_id/files

    describe('GET/agents/groups/:group_id/files/:filename', function() {

        it('Request', function(done) {

            request(common.url)
            .get("/agents/groups/webserver/files/cis_debian_linux_rcl.txt")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group name', function(done) {
            request(common.url)
            .get("/agents/groups/wñ!/files/cis_debian_linux_rcl.txt")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // GET/agents/groups/:group_id/files/:filename

    describe('DELETE/agents/:agent_id/group', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/001/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

        it('Errors: ID is not present', function(done) {

            request(common.url)
            .delete("/agents/54952/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);

                res.body.error.should.equal(1701);
                res.body.message.should.be.type('string');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .delete("/agents/abc/group")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

    });  // DELETE/agents/:agent_id/group

    describe('DELETE/agents/groups/:group_id', function() {

        it('Request', function(done) {

            request(common.url)
            .delete("/agents/groups/webserver")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                done();
            });
        });

        it('Params: Bad group id', function(done) {
            request(common.url)
            .delete("/agents/groups/webserverñ")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(601);
                done();
            });
        });

    });  // DELETE/agents/groups/:group_id

    describe('PUT/agents/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('string');
                done();
            });
        });

    });  // PUT/agents/restart

    describe('PUT/agents/:agent_id/restart', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/001/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.should.be.type('object');
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .put("/agents/abc/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(600);
                done();
            });
        });

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .put("/agents/000/restart")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);
                res.body.data.should.have.properties(['msg', 'failed_ids', 'affected_agents']);

                res.body.data.failed_ids[0].error.code.should.equal(1703);
                done();
            });
        });

    });  // PUT/agents/:agent_id/restart


    describe('GET/agents/purgeable/:timeframe', function() {

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .get("/agents/purgeable/0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                //res.body.data.totalItems.should.be.above(0);
                res.body.data.should.have.properties(['items'/*, 'totalItems'*/, 'timeframe']);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['id', 'name']);
                res.body.data.items[0].id.should.be.equal("001");
                done();
            });
        });

        it('Params: timeframe not valid', function(done) {
            request(common.url)
            .get("/agents/purgeable/wrongTimeframe")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(617);
                done();
            });
        });

    });  // GET/agents/purgeable/:timeframe

    describe('PUT/agents/purgeable/:timeframe', function() {
        before(function(done) {
            request(common.url)
            .put("/agents/testPurgeAgent")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);
                res.body.error.should.equal(0);
                purge_id = res.body.data.id;
                done();
            });
        });

        it('Request', function(done) {
            this.timeout(common.timeout);

            request(common.url)
            .get("/agents/purgeable/1d")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                //res.body.data.totalItems.should.be.above(0);
                res.body.data.should.have.properties(['items'/*, 'totalItems'*/, 'timeframe']);
                res.body.data.items.should.be.instanceof(Array)
                res.body.data.items[0].should.have.properties(['id', 'name']);
                res.body.data.items[0].id.should.be.equal(purge_id);
                done();
            });
        });

        it('Params: timeframe not valid', function(done) {
            request(common.url)
            .get("/agents/purgeable/wrongTimeframe")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(617);
                done();
            });
        });
    });  // GET/agents/purgeable/:timeframe

    describe('POST/agents/purge', function() {

        it('Request', function(done) {
            request(common.url)
            .post("/agents/purge")
            .send({'timeframe':'1d', 'verbose':true})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error','data']);
                res.body.error.should.be.equal(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(['id','name']);
                res.body.data.items[0].id.should.be.equal(purge_id);

                done();
            });
        });

        it('Bad param: timeframe', function(done) {
            request(common.url)
            .post("/agents/purge")
            .send({'timeframe':'wrongTimeframe'})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(617);
                done();
            });
        });

        it('Bad param: verbose', function(done) {
            request(common.url)
            .post("/agents/purge")
            .send({'timeframe':'1d', 'verbose':'trtrerej'})
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(400)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(618);
                done();
            });
        });
    }); // POST/agents/purge

});  // Agents
