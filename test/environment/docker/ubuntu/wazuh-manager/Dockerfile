FROM ubuntu:18.04

ARG wazuh_branch
ARG wazuh_api_branch

# enable SSH
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:wazuh' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22

# install dependencies
RUN apt-get install python python-pip python3 python3-pip git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release sqlite3 sudo -y

# install Wazuh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout ${wazuh_branch}
# build Python dependencies
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

# wazuh-documentation dependencies
RUN pip3 install Sphinx==1.6.5 sphinx-rtd-theme==0.2.4 sphinxcontrib-images==0.7.0 sphinxprettysearchresults==0.3.5

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest defusedxml ptvsd pydevd-pycharm~=191.6605.12 freezegun

# install and configure Wazuh API
RUN curl -sL https://deb.nodesource.com/setup_12.x | bash - && apt-get install -y nodejs && npm config set user 0
RUN git clone https://github.com/wazuh/wazuh-api && cd /wazuh-api && git checkout ${wazuh_api_branch} && ./install_api.sh && npm install mocha -g && npm install glob supertest mocha should moment mochawesome

# install ZSH
RUN apt-get install zsh -y
RUN cd /root && sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# copy script for running mocha tests
COPY run_mocha_tests.sh /wazuh-api

# copy entrypoint and configuration files
COPY entrypoint.sh /scripts/entrypoint.sh
COPY master-ossec.conf /scripts/master-ossec.conf
COPY worker-ossec.conf /scripts/worker-ossec.conf
