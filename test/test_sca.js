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


describe('SecurityConfigurationAssessment', function() {

    ca_fields = ['score', 'policy_id', 'references', 'name',
                 'description', 'pass', 'fail', 'start_scan', 'end_scan'];

    describe('GET/sca/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/sca/000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/sca/000?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/sca/000?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
                done();
            });
        });

        it('Sort', function(done) {
            request(common.url)
            .get("/sca/000?sort=-score")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/sca/000?search=ssh")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/sca/abc")
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
            .get("/sca/9999999")
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

        it('Filters: Invalid filter', function(done) {
            request(common.url)
            .get("/sca/000?random")
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
            .get("/sca/000?random&name=CIS")
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

        it('Filters: query', function(done) {
            request(common.url)
            .get("/sca/000?q=pass>0;fail<1000")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.integer;
                res.body.data.items.should.be.instanceof(Array);
                done();
            });
        });

        it('Filters: name', function(done) {
            request(common.url)
            .get("/sca/000?name=System%20audit%20for%20Unix%20based%20systems&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.integer;
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });

        it('Filters: references', function(done) {
            request(common.url)
            .get("/sca/000?references=https://www.ssh.com/ssh/&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.integer;
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(ca_fields);
                done();
            });
        });
    
        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/sca/000?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
                done();
            });
        });
    });  // GET/sca/:agent_id

    describe('GET/sca/:agent_id/checks/:policy_id', function() {

        sca_check_fields = ['condition', 'status', 'remediation', 'result',
                            'rationale', 'policy_id', 'title', 'id',
                            'reason', 'description', 'compliance', 'rules']

        it('Request', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.be.string;
                done();
            });
        });

        it('Pagination', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?offset=0&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.be.string;
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
                done();
            });
        });

        it('Sort', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?sort=-")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.be.string;
                done();
            });
        });

        it('Search', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?search=2")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.be.string;
                done();
            });
        });

        it('Params: Bad agent id', function(done) {
            request(common.url)
            .get("/sca/abc/checks/unix_audit")
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
            .get("/sca/9999999/checks/unix_audit")
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

        it('Check not found', function(done) {
            request(common.url)
            .get("/sca/000/checks/not_exists")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.equal(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items.should.have.length(0);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?limit=0")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1406);
                done();
            });
        });

        it('Filters: title', function(done) {
            request(common.url)
            .get("/sca/000/checks/cis_debian9_L2?&title=Ensure%20events%20that%20modify%20the%20system%27s%20Mandatory%20Access%20Controls%20are%20collected%20%28SELinux%29&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: incomplete title', function(done) {
            request(common.url)
            .get("/sca/000/checks/cis_debian9_L2?title=Ensure%20events%20that&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.equal(0);
                res.body.data.items.should.be.instanceof(Array);

                done();
            });

        });

        it('Filters: description', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?description=Turn%20on%20the%20auditd%20daemon%20to%20record%20system%20events.&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: rationale', function(done) {
            request(common.url)
            .get("/sca/000/checks/cis_debian9_L2?rationale=In%20high%20security%20contexts%2C%20the%20risk%20of%20detecting%20unauthorized%20access%20or%20nonrepudiation%20exceeds%20the%20benefit%20of%20the%20system%27s%20availability.&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: remediation', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?remediation=Change%20the%20Port%20option%20value%20in%20the%20sshd_config%20file.&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: file', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?file=/etc/ssh/sshd_config&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: references', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?references=https://www.thegeekdiary.com/understanding-etclogin-defs-file&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: result', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?result=failed&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: command', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?command=systemctl%20is-enabled%20auditd&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: status', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?status=Not%20applicable&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: reason', function(done) {
            request(common.url)
            .get("/sca/000/checks/cis_debian9_L2?reason=Could%20not%20open%20file%20%27%2Fetc%2Fdefault%2Fgrub%27&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

        it('Filters: condition', function(done) {
            request(common.url)
            .get("/sca/000/checks/unix_audit?condition=all&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(sca_check_fields);

                done();
            });

        });

    });  // GET/sca/:agent_id/pci

});  // Security Configuration Assessment
