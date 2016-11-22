
Pre-requisites:

    $ npm install apidoc -g

Generate documentation:

    $ cd $PATH/wazuh-api/doc
    $ ./generate_rst.py /$PATH/wazuh-documentation/source/ossec_api_reference.rst
    $ cd /$PATH/wazuh-documentation/
    $ make html

one-line command:

    ./generate_rst.py /$PATH/wazuh-documentation/source/ossec_api_reference.rst && cd /$PATH/wazuh-documentation/ && make html && cd -

Review **ossec_api_reference.html,** specially *Example Response* section.
