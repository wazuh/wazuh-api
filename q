[1mdiff --git a/controllers/mitre.js b/controllers/mitre.js[m
[1mindex 52a1bd9..39fcacc 100644[m
[1m--- a/controllers/mitre.js[m
[1m+++ b/controllers/mitre.js[m
[36m@@ -24,6 +24,7 @@[m [mvar router = require('express').Router();[m
  * @apiParam {String} [attack] Filter by attack ID.[m
  * @apiParam {String} [phase] Filter by phase name.[m
  * @apiParam {String} [platform] Filter by platform name.[m
[32m+[m[32m * @apiParam {String} [search] Looks for elements with the specified string.[m
  *[m
  * @apiDescription Returns information from Mitre database[m
  *[m
[36m@@ -39,7 +40,7 @@[m [mrouter.get('/', cache(), function(req, res) {[m
     var data_request = {'function': '/mitre', 'arguments': {}};[m
     var filters = {'offset': 'numbers', 'limit': 'numbers', 'q': 'query_param',[m
                    'attack': 'search_param', 'phase': 'search_param',[m
[31m-                   'platform': 'names', 'sort':'sort_param'};[m
[32m+[m[32m                   'platform': 'names', 'search': 'search_param', 'sort':'sort_param'};[m
 [m
     if (!filter.check(req.query, filters, req, res))  // Filter with error[m
         return;[m
[36m@@ -54,6 +55,8 @@[m [mrouter.get('/', cache(), function(req, res) {[m
         data_request['arguments']['phase'] = req.query.phase;[m
     if ('platform' in req.query)[m
         data_request['arguments']['platform'] = req.query.platform;[m
[32m+[m[32m    if ('search' in req.query)[m
[32m+[m[32m        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);[m
     if ('sort' in req.query)[m
         data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);[m
     if ('q' in req.query)[m
[36m@@ -63,3 +66,75 @@[m [mrouter.get('/', cache(), function(req, res) {[m
 })[m
 [m
 module.exports = router;[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m
[32m+[m[32m// /**[m
[32m+[m[32m//  * Wazuh RESTful API[m
[32m+[m[32m//  * Copyright (C) 2015-2019 Wazuh, Inc. All rights reserved.[m
[32m+[m[32m//  * Wazuh.com[m
[32m+[m[32m//  *[m
[32m+[m[32m//  * This program is a free software; you can redistribute it[m
[32m+[m[32m//  * and/or modify it under the terms of the GNU General Public[m
[32m+[m[32m//  * License (version 2) as published by the FSF - Free Software[m
[32m+[m[32m//  * Foundation.[m
[32m+[m[32m//  */[m
[32m+[m
[32m+[m
[32m+[m[32m// var router = require('express').Router();[m
[32m+[m
[32m+[m[32m// /**[m
[32m+[m[32m//  * @api {get} /mitre Get information from Mitre database[m
[32m+[m[32m//  * @apiName GetMitre[m
[32m+[m[32m//  * @apiGroup Info[m
[32m+[m[32m//  *[m
[32m+[m[32m//  * @apiParam {Number} [offset] First element to return in the collection.[m
[32m+[m[32m//  * @apiParam {Number} [limit=10] Maximum number of elements to return.[m
[32m+[m[32m//  * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.[m
[32m+[m[32m//  * @apiParam {String} [q] Query to filter results by. For example q="attack=T1010"[m
[32m+[m[32m//  * @apiParam {String} [attack] Filter by attack ID.[m
[32m+[m[32m//  * @apiParam {String} [phase] Filter by phase name.[m
[32m+[m[32m//  * @apiParam {String} [platform] Filter by platform name.[m
[32m+[m[32m//  * @apiParam {String} [search] Looks for elements with the specified string.[m
[32m+[m[32m//  *[m
[32m+[m[32m//  * @apiDescription Returns information from Mitre database[m
[32m+[m[32m//  *[m
[32m+[m[32m//  * @apiExample {curl} Example usage*:[m
[32m+[m[32m//  *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/mitre?limit=2&offset=4&pretty"[m
[32m+[m[32m//  *[m
[32m+[m[32m//  */[m
[32m+[m[32m// router.get('/', cache(), function(req, res) {[m
[32m+[m[32m//     logger.debug(req.connection.remoteAddress + " GET /mitre");[m
[32m+[m
[32m+[m[32m//     req.apicacheGroup = "mitre";[m
[32m+[m
[32m+[m[32m//     var data_request = {'function': '/mitre', 'arguments': {}};[m
[32m+[m[32m//     var filters = {'offset': 'numbers', 'limit': 'numbers', 'q': 'query_param',[m
[32m+[m[32m//                    'attack': 'search_param', 'phase': 'search_param',[m
[32m+[m[32m//                    'platform': 'names', 'sort':'sort_param'};[m
[32m+[m
[32m+[m[32m//     if (!filter.check(req.query, filters, req, res))  // Filter with error[m
[32m+[m[32m//         return;[m
[32m+[m
[32m+[m[32m//     if ('offset' in req.query)[m
[32m+[m[32m//         data_request['arguments']['offset'] = Number(req.query.offset);[m
[32m+[m[32m//     if ('limit' in req.query)[m
[32m+[m[32m//         data_request['arguments']['limit'] = Number(req.query.limit);[m
[32m+[m[32m//     if ('attack' in req.query)[m
[32m+[m[32m//         data_request['arguments']['attack'] = req.query.attack;[m
[32m+[m[32m//     if ('phase' in req.query)[m
[32m+[m[32m//         data_request['arguments']['phase'] = req.query.phase;[m
[32m+[m[32m//     if ('platform' in req.query)[m
[32m+[m[32m//         data_request['arguments']['platform'] = req.query.platform;[m
[32m+[m[32m//     if ('sort' in req.query)[m
[32m+[m[32m//         data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);[m
[32m+[m[32m//     if ('q' in req.query)[m
[32m+[m[32m//         data_request['arguments']['q'] = req.query.q;[m
[32m+[m
[32m+[m[32m//     execute.exec(python_bin, [wazuh_control], data_request, function (data) { res_h.send(req, res, data); });[m
[32m+[m[32m// })[m
[32m+[m
[32m+[m[32m// module.exports = router;[m
[1mdiff --git a/test/test_mitre.js b/test/test_mitre.js[m
[1mindex cf4f2fc..c042795 100644[m
[1m--- a/test/test_mitre.js[m
[1m+++ b/test/test_mitre.js[m
[36m@@ -512,6 +512,43 @@[m [mdescribe('Mitre', function() {[m
             });[m
         });[m
 [m
[32m+[m[32m        it('Search', function(done) {[m
[32m+[m[32m            request(common.url)[m
[32m+[m[32m            .get("/mitre?search=points%to%explorer.exe")[m
[32m+[m[32m            .auth(common.credentials.user, common.credentials.password)[m
[32m+[m[32m            .expect("Content-type",/json/)[m
[32m+[m[32m            .expect(200)[m
[32m+[m[32m            .end(function(err,res){[m
[32m+[m[32m                if (err) return done(err);[m
[32m+[m
[32m+[m[32m                res.body.should.have.properties(['error', 'data']);[m
[32m+[m
[32m+[m[32m                res.body.error.should.equal(0);[m
[32m+[m[32m                res.body.data.totalItems.should.be.above(0);[m
[32m+[m[32m                res.body.data.items.should.be.instanceof(Array);[m
[32m+[m[32m                res.body.data.items[0].should.be.string;[m
[32m+[m[32m                done();[m
[32m+[m[32m            });[m
[32m+[m[32m        });[m
[32m+[m
[32m+[m[32m        it('Search (returns 0 items)', function(done) {[m
[32m+[m[32m            request(common.url)[m
[32m+[m[32m            .get("/mitre?search=test_test_test")[m
[32m+[m[32m            .auth(common.credentials.user, common.credentials.password)[m
[32m+[m[32m            .expect("Content-type",/json/)[m
[32m+[m[32m            .expect(200)[m
[32m+[m[32m            .end(function(err,res){[m
[32m+[m[32m                if (err) return done(err);[m
[32m+[m
[32m+[m[32m                res.body.should.have.properties(['error', 'data']);[m
[32m+[m
[32m+[m[32m                res.body.error.should.equal(0);[m
[32m+[m[32m                res.body.data.totalItems.should.be.equal(0);[m
[32m+[m[32m                res.body.data.items.should.be.instanceof(Array);[m
[32m+[m[32m                done();[m
[32m+[m[32m            });[m
[32m+[m[32m        });[m
[32m+[m
     });  // GET /mitre[m
 [m
 });  // Mitre[m
