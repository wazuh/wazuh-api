/**
 * API RESTful for OSSEC
 * Copyright (C) 2015-2019 Wazuh, Inc.All rights reserved.
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


describe('Mitre', function() {

    keys = ['id', 'json', 'platform_name', 'phase_name']

    describe('GET/sca/:agent_id', function() {

        it('Request', function(done) {
            request(common.url)
            .get("/mitre")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);
                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 1', function(done) {
            request(common.url)
            .get("/mitre?offset=4&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 5', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=5")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(5);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit = 10', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=10")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Pagination: limit > 10', function(done) {
            request(common.url)
            .get("/mitre?offset=10&limit=15")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Retrieve all elements with limit=0', function(done) {
            request(common.url)
            .get("/mitre?limit=0")
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

        let test_sort_id = 0;

        it('Sort: +id', function(done) {
            request(common.url)
            .get("/mitre?sort=+id")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);

                test_sort_id = res.body.data.items[0].id

                done();
            });
        });

        it('Sort: -id', function(done) {
            request(common.url)
            .get("/mitre?sort=-id")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(10);
                res.body.data.items[0].should.have.properties(keys);

                res.body.data.items[0].id.should.be.above(test_sort_id)

                done();
            });
        });

        it('Filters: id', function(done) {
            request(common.url)
            .get("/mitre?id=T1101")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: id (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?id=T99")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: phase_name=initial access', function(done) {
            request(common.url)
            .get("/mitre?phase_name=initial%20access")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: phase_name=persistence', function(done) {
            request(common.url)
            .get("/mitre?phase_name=persistence")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: phase_name (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?phase_name=wrong%20phase")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: platform_name=linux', function(done) {
            request(common.url)
            .get("/mitre?platform_name=linux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name=macos', function(done) {
            request(common.url)
            .get("/mitre?platform_name=macos")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name=windows', function(done) {
            request(common.url)
            .get("/mitre?platform_name=windows")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name=windows,phase_name=persistence', function(done) {
            request(common.url)
            .get("/mitre?platform_name=windows&phase_name=persistence")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name=linux,phase_name=execution', function(done) {
            request(common.url)
            .get("/mitre?platform_name=linux&phase_name=execution")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name=macos,phase_name=impact', function(done) {
            request(common.url)
            .get("/mitre?platform_name=linux&phase_name=impact")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: platform_name (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?platform_name=hpux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: q=id=T1015', function(done) {
            request(common.url)
            .get("/mitre?q=id=T1015")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q=platform_name=linux', function(done) {
            request(common.url)
            .get("/mitre?q=platform_name=linux&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q=phase_name=execution', function(done) {
            request(common.url)
            .get("/mitre?q=phase_name=execution&limit=1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
                res.body.data.items[0].should.have.properties(keys);
                done();
            });
        });

        it('Filters: q (request returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?q=id=T1")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(0);
                done();
            });
        });

        it('Filters: q (wrong query 1)', function(done) {
            request(common.url)
            .get("/mitre?q=phase_names=impact")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

        it('Filters: q (wrong query 2)', function(done) {
            request(common.url)
            .get("/mitre?q=system=linux")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

        it('Filters: q (wrong query 3)', function(done) {
            request(common.url)
            .get("/mitre?q=attack_id=T1100")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'message']);
                res.body.error.should.equal(1408);
                done();
            });
        });

        it('Filters: select=id,phase_name,platform_name', function(done) {
            request(common.url)
            .get("/mitre?select=id,phase_name,platform_name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(['id', 'phase_name', 'platform_name'])
                done();
            });
        });

        it('Filters: select=id,json,platform_name', function(done) {
            request(common.url)
            .get("/mitre?select=id,json,platform_name")
            .auth(common.credentials.user, common.credentials.password)
            .expect("Content-type",/json/)
            .expect(200)
            .end(function(err,res){
                if (err) return done(err);

                res.body.should.have.properties(['error', 'data']);

                res.body.error.should.equal(0);
                res.body.data.totalItems.should.be.above(0);
                res.body.data.items.length.should.be.belowOrEqual(10);
                res.body.data.items.should.be.instanceof(Array);
                res.body.data.items[0].should.have.properties(['id', 'json', 'platform_name'])
                done();
            });
        });

        it('Filters: select=platform (wrong field)', function(done) {
            request(common.url)
            .get("/mitre?select=platform")
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

        it('Search', function(done) {
            request(common.url)
            .get("/mitre?search=points%to%explorer.exe")
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

        it('Search (returns 0 items)', function(done) {
            request(common.url)
            .get("/mitre?search=test_test_test")
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

    });  // GET /mitre

});  // Mitre
