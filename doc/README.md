# Generating Wazuh API Reference documentation

## Environment
Build vagrant envinroment using files available under `build_environment` directory.

Environment variable `WAZUH_GIT_PATH` needs to be set before deploying Vagrant environment:
* In windows:
    ```powershell
    > Set-Item -path env:WAZUH_GIT_PATH -value C:\Users\Marta\Documents\GitHub
    ```
* In linux:
    ```shellsession
    # export WAZUH_GIT_PATH=/home/marta/documents/github
    ```

## Generate documentation:

```shellsession
$ WAZUH_REPO=/home/vagrant/GitHub
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
