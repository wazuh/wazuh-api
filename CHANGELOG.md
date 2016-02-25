# Change Log
All notable changes to this project will be documented in this file.

## [v1.2] - 2016-03-??
### Added
- ?

### Fixed
- Problem importing xmljson package in Python

## [v1.1] - 2016-02-24
### Added
- Agents
 - DELETE /agents/:agent_id
 - POST /agents
 - PUT /agents/:agent_id/restart
 - PUT /agents/:agent_name
 
- Manager
 - GET /manager/configuration
 - GET /manager/configuration/test
 - GET /manager/stats
 - GET /manager/stats/hourly
 - GET /manager/stats/weekly
 - GET /manager/status
 - PUT /manager/restart
 - PUT /manager/start
 - PUT /manager/stop
 
- Rootcheck
 - DELETE /rootcheck
 - DELETE /rootcheck/:agent_id
 - GET /rootcheck/:agent_id
 - GET /rootcheck/:agent_id/last_scan
 - PUT /rootcheck
 - PUT /rootcheck/:agent_id
 
- Syscheck
 - DELETE /syscheck
 - DELETE /syscheck/:agent_id
 - GET /syscheck/:agent_id/files/changed
 - GET /syscheck/:agent_id/last_scan
 - PUT /syscheck
 - PUT /syscheck/:agent_id


### Changed
- Directory structure
- HTTP verbs for *agents* resource.
- Requests */agents/sysrootcheck* have been split:
 - /syscheck
 - /rootcheck

 
## [v1.0] - 2015-11-08
- Inital version
