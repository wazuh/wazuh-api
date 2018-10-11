# Generating Wazuh API Reference documentation

## Pre-requisites:

```shellsession
$ npm install apidoc -g
$ pip install requests
```

## Prepare OSSEC:

1. Install OSSEC (it must be a new installation).
2. Install API.
3. Configure API: https and auth (foo:bar).
4. Add a new (active) agent.
5. Set `syscheck.sleep=0` and `wazuh_database.sync_syscheck=1`.
6. Configure a cluster.
7. Restart OSSEC.
8. Set `config.experimental_features  = true;` in the API configuration.
9. Restart API.

## Generate documentation:

```shellsession
$ WAZUH_REPO=/home/wazuh
$ cd $WAZUH_REPO/wazuh-api/doc
$ ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst
$ cd $WAZUH_REPO/wazuh-documentation/
$ make html
```

one-line command:
```shellsession
$ ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst && cd $WAZUH_REPO/wazuh-documentation/ && make html && cd -
```

Review **wazuh-documentation/source/user-manual/api/reference.rst**, specially *Example Response* section.
