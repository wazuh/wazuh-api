#!/usr/bin/env bash
/var/ossec/framework/python/bin/python3 ./generate_rst.py /wazuh-documentation/source/user-manual/api/reference.rst
cd /wazuh-documentation
make html
