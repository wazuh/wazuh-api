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
var common  = require('./common.js');


process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Syscollector', function() {


  describe('GET/syscollector/:agent_id/os', function() {

    var expected_sysname = "";
    var expected_hostname = "";
    var expected_architecture = "";
    before(function(done) {
        request(common.url)
        .get("/agents/001")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.should.have.properties(['os', 'manager_host']);
            res.body.data.os.should.have.properties(['arch', 'platform']);
            expected_sysname = res.body.data.os.platform;
            expected_hostname = res.body.data.manager_host;
            expected_architecture = res.body.data.os.arch;
            done();
        });
      });

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/os")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.be.an.array;
              res.body.data.should.have.properties(['sysname', 'scan_id', 'os_name', 'scan_time', 'hostname', 'os_version', 'version', 'architecture', 'release']);
              res.body.data.sysname.should.be.equal(expected_sysname);
              res.body.data.hostname.should.be.equal(expected_hostname);
              res.body.data.architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/os?select=os_version,sysname,release")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['os_version', 'sysname', 'release']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/os?select=wrongParam")
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

  });  // GET/syscollector/:agent_id/os


  describe('GET/syscollector/:agent_id/hardware', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.be.an.array;
              res.body.data.should.have.properties(['ram_free', 'scan_id', 'board_serial', 'scan_time', 'cpu_name', 'cpu_cores', 'ram_total', 'cpu_mhz']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware?select=ram_free,board_serial,cpu_name,ram_total")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.should.have.properties(['ram_free', 'board_serial', 'cpu_name', 'ram_total']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/hardware?select=wrongParam")
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

  });  // GET/syscollector/:agent_id/os


  describe('GET/syscollector/:agent_id/packages', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/001/packages")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?select=scan_id,description,scan_time,architecture")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'description', 'scan_time', 'architecture']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?select=wrongParam")
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

      it('Pagination', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?offset=0&limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Wrong limit', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?offset=0&limit=1a")
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

      it('Sort -', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=-name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
              done();
          });
      });

      it('Sort +', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=+name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
              done();
          });
      });

      it('Wrong Sort', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?sort=-wrongParameter")
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

    var expected_name = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/001/packages?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['name']);
            expected_name = res.body.data.items[0].name;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?search="+expected_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              res.body.data.items[0].name.should.be.equal(expected_name);
              done();
          });
      });

      var expected_vendor = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['vendor']);
              expected_vendor = res.body.data.items[0].vendor;
              done();
          });
      });

      it('Filter vendor', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?vendor=" + expected_vendor)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['vendor']);
              res.body.data.items[0].vendor.should.be.equal(expected_vendor);
              done();
          });
      });

      var expected_filter_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['name']);
              expected_filter_name = res.body.data.items[0].name;
              done();
          });
      });

      it('Filter name', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?name=" + expected_filter_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[0].name.should.be.equal(expected_filter_name);
              done();
          });
      });

      var expected_architecture = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['architecture']);
              expected_architecture = res.body.data.items[0].architecture;
              done();
          });
      });

      it('Filter architecture', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?architecture=" + expected_architecture)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['architecture']);
              res.body.data.items[0].architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      var expected_format = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/001/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['format']);
              expected_format = res.body.data.items[0].format;
              done();
          });
      });

      it('Filter format', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?format=" + expected_format)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['format']);
              res.body.data.items[0].format.should.be.equal(expected_format);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/001/packages?wrongFilter=value")
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

  });  // GET/syscollector/:agent_id/packages


  describe('GET/syscollector/packages', function() {

      it('Request', function(done) {
          request(common.url)
          .get("/syscollector/packages")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'agent_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Selector', function(done) {
          request(common.url)
          .get("/syscollector/packages?select=scan_id,description,scan_time,architecture")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'description', 'scan_time', 'architecture']);
              done();
          });
      });

      it('Not allowed selector', function(done) {
          request(common.url)
          .get("/syscollector/packages?select=wrongParam")
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

      it('Pagination', function(done) {
          request(common.url)
          .get("/syscollector/packages?offset=0&limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['scan_id', 'agent_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              done();
          });
      });

      it('Wrong limit', function(done) {
          request(common.url)
          .get("/syscollector/packages?offset=0&limit=1a")
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

      it('Sort -', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=-name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[0].name.should.not.be.greaterThan(res.body.data.items[1].name);
              done();
          });
      });

      it('Sort +', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=+name&limit=2")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(2);
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[1].should.have.properties(['name']);
              res.body.data.items[1].name.should.not.be.greaterThan(res.body.data.items[0].name);
              done();
          });
      });

      it('Wrong Sort', function(done) {
          request(common.url)
          .get("/syscollector/packages?sort=-wrongParameter")
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

    var expected_name = "";
    before(function(done) {
        request(common.url)
        .get("/syscollector/packages?limit=1")
        .auth(common.credentials.user, common.credentials.password)
        .expect("Content-type",/json/)
        .expect(200)
        .end(function(err,res){
            if (err) return done(err);
            res.body.should.have.properties(['error', 'data']);
            res.body.error.should.equal(0);
            res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
            res.body.data.items[0].should.have.properties(['name']);
            expected_name = res.body.data.items[0].name;
            done();
        });
      });

      it('Search', function(done) {
          request(common.url)
          .get("/syscollector/packages?search="+expected_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);

              res.body.should.have.properties(['error', 'data']);

              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['scan_id', 'vendor', 'description', 'format', 'scan_time', 'version', 'architecture', 'name']);
              res.body.data.items[0].name.should.be.equal(expected_name);
              done();
          });
      });

      var expected_vendor = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['vendor']);
              expected_vendor = res.body.data.items[0].vendor;
              done();
          });
      });

      it('Filter vendor', function(done) {
          request(common.url)
          .get("/syscollector/packages?vendor=" + expected_vendor)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['vendor']);
              res.body.data.items[0].vendor.should.be.equal(expected_vendor);
              done();
          });
      });

      var expected_filter_name = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['name']);
              expected_filter_name = res.body.data.items[0].name;
              done();
          });
      });

      it('Filter name', function(done) {
          request(common.url)
          .get("/syscollector/packages?name=" + expected_filter_name)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['name']);
              res.body.data.items[0].name.should.be.equal(expected_filter_name);
              done();
          });
      });

      var expected_architecture = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['architecture']);
              expected_architecture = res.body.data.items[0].architecture;
              done();
          });
      });

      it('Filter architecture', function(done) {
          request(common.url)
          .get("/syscollector/packages?architecture=" + expected_architecture)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['architecture']);
              res.body.data.items[0].architecture.should.be.equal(expected_architecture);
              done();
          });
      });

      var expected_format = "";
      before(function(done) {
          request(common.url)
          .get("/syscollector/packages?limit=1")
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array).and.have.lengthOf(1);
              res.body.data.items[0].should.have.properties(['format']);
              expected_format = res.body.data.items[0].format;
              done();
          });
      });

      it('Filter format', function(done) {
          request(common.url)
          .get("/syscollector/packages?format=" + expected_format)
          .auth(common.credentials.user, common.credentials.password)
          .expect("Content-type",/json/)
          .expect(200)
          .end(function(err,res){
              if (err) return done(err);
              res.body.should.have.properties(['error', 'data']);
              res.body.error.should.equal(0);
              res.body.data.totalItems.should.be.above(0);
              res.body.data.items.should.be.instanceof(Array)
              res.body.data.items[0].should.have.properties(['format']);
              res.body.data.items[0].format.should.be.equal(expected_format);
              done();
          });
      });

      it('Wrong filter', function(done) {
          request(common.url)
          .get("/syscollector/packages?wrongFilter=value")
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

  });  // GET/syscollector/packages



});  // Syscollector
