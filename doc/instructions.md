
Pre-requisites:

    $ npm install apidoc -g

Generate documentation:

    $ cd $PATH/wazuh-api/doc
    $ ./generate_rst.py /$PATH/wazuh-documentation/source/user-manual/api/reference.rst
    $ cd /$PATH/wazuh-documentation/
    $ make html

one-line command:

    ./generate_rst.py /$PATH/wazuh-documentation/source/user-manual/api/reference.rst && cd /$PATH/wazuh-documentation/ && make html && cd -

Review **wazuh-documentation/source/user-manual/api/reference.rst**, specially *Example Response* section.
