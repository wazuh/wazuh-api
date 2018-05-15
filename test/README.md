# Mocha tests

## Requirements

 * API installed and configurated (Configure API: https and auth (foo:bar)).
 * Packages npm installed: `glob`, `supertest`, `mocha`, `should`, `moment` and `getos`.
 
    ``` npm install glob supertest mocha should moment getos ```

 * Cluster configurated and running with 2 connected nodes: `master` and `client`.
 * A connected agent with id `001`.
 * DB syscheck activated: Add `wazuh_database.sync_syscheck=1` to the file `/var/ossec/etc/local_internal_options.conf`.
 * Restart wazuh-manager.

## Run all tests
    $ mocha test/
