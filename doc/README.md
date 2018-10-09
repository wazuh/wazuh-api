# Generating Wazuh API Reference documentation

## Pre-requisites:

```shellsession
$ npm install apidoc -g
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
9. Execute requests:
10. Restart API.
```shellsession
$ curl -u foo:bar -k -X POST -d '{"name":"server001","ip":"10.0.0.62"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
$ curl -u foo:bar -k -X POST -d '{"name":"dmz001","ip":"10.0.0.12"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
$ curl -u foo:bar -k -X POST -d '{"name":"main_database","ip":"10.0.0.15"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
$ curl -u foo:bar -k -X POST -d '{"name":"dmz002","ip":"10.0.0.14"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
$ curl -u foo:bar -k -X POST -d '{"name":"server002","ip":"10.0.0.20"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
$ curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/groups/dmz?pretty"
$ curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/groups/webserver?pretty"
$ curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/groups/database?pretty"
$ curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/001/group/dmz?pretty
$ curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/002/group/webserver?pretty
$ curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/003/group/database?pretty
$ curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/004/group/dmz?pretty
$ curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/005/group/webserver?pretty
```
11. vim /var/ossec/etc/shared/dmz/agent.conf
```xml
<agent_config os="Linux">
    <localfile>
        <location>/var/log/linux.log</location>
        <log_format>syslog</log_format>
    </localfile>
</agent_config>
```

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
