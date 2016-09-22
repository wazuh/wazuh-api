# Change Log
All notable changes to this project will be documented in this file.


## [v1.3.0] - 2016-10-??
### Added
- Scripts:
 - install_api.sh
 - configure_api.sh
- Parameters:
 - Pretty JSON (?pretty)
 - Pagination: offset & limit
 - Search
 - Sort
- Requests:
 - Agents
  - GET /agents/summary (Get agents summary)
  - PUT /agents/restart (Restart all agents)
 - Manager
  - GET /manager/info (Get manager information)
  - GET /manager/logs (Get ossec.log)
  - GET /manager/logs/summary (Get summary of ossec.log)
 - Decoders
  - GET /decoders (Get all decoders)
  - GET /decoders/:decoder_name (Get decoders by name)
  - GET /decoders/files (Get all decoders files)
  - GET /decoders/parents (Get all parent decoders)
 - Rules
  - GET /rules (Get all rules)
  - GET /rules (Get rules by id)
  - GET /rules/files (Get files of rules)
  - GET /rules/groups (Get rule groups)
  - GET /rules/pci (Get rule pci requirements)
 - Rootcheck
  - GET /rootcheck/:agent_id/cis (Get rootcheck CIS requirements)
  - GET /rootcheck/:agent_id/pci (Get rootcheck pci requirements)

- Wazuh framework: Manage OSSEC Wazuh from python.
- Unit tests
- Cache (750ms) for GET Requests

### Changed
- Improved API service.
- Improved input validation.
- Improved Error Handling.
- Settings in /api/configuration.
- By default, API is installed using HTTP.
- Requests:
 - Improved:
  - GET /rootcheck/:agent_id (Get rootcheck database)
  - GET /syscheck/:agent_id (Get syscheck files)

### Removed
- Requests that require root privileges:
 - /manager/configuration/test
 - /manager/start,stop,restart


## [v1.2.1] - 2016-07-25
### Fixed
- Issue installing API as service.


## [v1.2] - 2016-04-13
### Added
- Run API as service
- API Versioning
- Improved error handling
- Improved Cross-origin resource sharing (CORS)
- Automatic agent IP address registration
- Improved proxy server IP source extraction

### Changed
- NodeJS modules must be installed with *npm install*
- Response JSON: Field *response* changed to *data*.

### Fixed
- Problem importing xmljson package in Python
- Wrong HTTP Status Code in some specific cases


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
