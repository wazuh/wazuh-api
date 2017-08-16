
Pre-requisites:

    $ npm install apidoc -g

Prepare OSSEC:

    1. Install OSSEC (it must be a new installation)
    2. Install API
    3. Configure API: https and auth (foo:bar)
    4. Set syscheck.sleep=0
    5. Restart OSSEC
    6. Execute request:
      - curl -u foo:bar -k -X POST -d '{"name":"server001","ip":"10.0.0.62"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents"
      - curl -u foo:bar -k -X POST -d '{"name":"dmz001","ip":"10.0.0.12"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents"
      - curl -u foo:bar -k -X POST -d '{"name":"main_database","ip":"10.0.0.15"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents"
      - curl -u foo:bar -k -X POST -d '{"name":"dmz002","ip":"10.0.0.14"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents"
      - curl -u foo:bar -k -X POST -d '{"name":"server002","ip":"10.0.0.20"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents"
      - curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/001/group/webserver
      - curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/002/group/dmz
      - curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/003/group/database
      - curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/004/group/dmz
      - curl -u foo:bar -k -X PUT https://127.0.0.1:55000/agents/005/group/webserver
     7. nano /var/ossec/etc/shared/webserver/agent.conf
        <agent_config os="Linux">
            <localfile>
                <location>/var/log/linux.log</location>
                <log_format>syslog</log_format>
            </localfile>
        </agent_config>

Generate documentation:

    $ WAZUH_REPO=/home/wazuh
    $ cd $WAZUH_REPO/wazuh-api/doc
    $ ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst
    $ cd $WAZUH_REPO/wazuh-documentation/
    $ make html

one-line command:

    ./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst && cd $WAZUH_REPO/wazuh-documentation/ && make html && cd -

Review **wazuh-documentation/source/user-manual/api/reference.rst**, specially *Example Response* section.
