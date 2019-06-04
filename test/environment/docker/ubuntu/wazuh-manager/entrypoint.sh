#!/usr/bin/env bash

if [ "X$3" == "Xmaster" ]; then
    cp /scripts/master-ossec.conf /var/ossec/etc/ossec.conf
elif [ "X$3" == "Xworker" ]; then
    cp /scripts/worker-ossec.conf /var/ossec/etc/ossec.conf
fi

# add cluster configuration
sed -i "s:<key></key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" /var/ossec/etc/ossec.conf
sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>no</disabled>|g" /var/ossec/etc/ossec.conf
sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" /var/ossec/etc/ossec.conf

if [ "X$3" != "Xmaster" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
fi

# enable syscheck DB
echo 'wazuh_database.sync_syscheck=1' >> /var/ossec/etc/local_internal_options.conf

# configure API for development
sed -i 's/config.logs = "info";/config.logs = "debug";/g' /var/ossec/api/configuration/config.js
sed -i 's/config.cache_enabled = "yes";/config.cache_enabled = "no";/g' /var/ossec/api/configuration/config.js
sed -i 's/config.experimental_features  = false;/config.experimental_features = true;/g' /var/ossec/api/configuration/config.js        

# disable HTTPS for mocha tests
sed -i 's/https/http/g' /wazuh-api/test/common.js

# start Wazuh
/var/ossec/bin/ossec-control start

# start Wazuh API
node /var/ossec/api/app.js &

/usr/bin/supervisord
