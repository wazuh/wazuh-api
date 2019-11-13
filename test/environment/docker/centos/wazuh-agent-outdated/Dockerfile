FROM centos:latest

RUN yum install which -y

RUN rpm --import http://packages.wazuh.com/key/GPG-KEY-WAZUH
COPY wazuh-repository.txt /etc/yum.repos.d/wazuh.repo

RUN yum install wazuh-agent-3.5.0 -y

COPY entrypoint.sh /scripts/entrypoint.sh
