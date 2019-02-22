#!/usr/bin/env bash

export WAZUH_REPO=/home/vagrant/GitHub
cd $WAZUH_REPO/wazuh-api/doc
./generate_rst.py $WAZUH_REPO/wazuh-documentation/source/user-manual/api/reference.rst
cd $WAZUH_REPO/wazuh-documentation/
make html
