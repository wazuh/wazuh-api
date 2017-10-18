# Change Log
All notable changes to this project will be documented in this file.

## [v3.0.0]
### Added
- Parameter in config.js file to configure the SSL version to use in the API.
- Added a new class on the Python framework: `InputValidation`.
- New request: Delete a list of groups - `DELETE /agents/groups - Params: {"ids":["id_1",...,"id_n"]}`
- Input Validation at framework level of `group_id` parameter.

### Fixed
- When adding a new agent, now it checks that its name is different than manager's name.


## [v2.1.1]
### Fixed
- Issue issue when deleting and restarting a list of agents
- Issue with socket comunication in authd.

## [v2.1.0]
### Added
- Added OS information to `GET /agent` request
- New request: Delete a list of agents - `DELETE /agents - Params: {"ids":["id_1", ..., "id_n"]}`
- New request: Restart a list of agents - `POST /agents/restart - Params: {"ids":["id_1", ..., "id_n"]}`

### Changed
- Support add/remove agents with ossec-authd running


## [v2.0.1] - 2017-07-25
### Fixed
- Issue when basic-auth is disabled.
- Regex for latest version in install_api.sh
- Wrong scan dates for syscheck and rootcheck.
- IP value always must be lowercase.

## [v2.0.0] - 2017-04-24
### Added
- **Wazuh v2.0** is required to run the API.
- API must be launched with root user, but it is run with ossec user.
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
      - POST /agents/insert (Insert agent)
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
 - API
    - GET /version

- Wazuh framework: Manage Wazuh from python.
- Unit tests
- Cache (750ms) for GET requests

### Changed
- Improved API service.
- Improved input validation.
- Improved Error Handling.
- Improved logging.
- Settings in /api/configuration.
- By default, API is installed using HTTP.
- xmljson is not necessary.
- apache-utils is not necessary.
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
