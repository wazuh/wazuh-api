FROM ubuntu:18.04

ARG wazuhbranch
ARG wazuhapibranch

# install supervisor just in case it isn't already installed
RUN apt-get update && apt-get install -y openssh-server supervisor

ADD supervisord.conf /etc/supervisor/conf.d/
ADD sshd.conf /etc/supervisor/conf.d/
RUN mkdir -p /var/run/sshd /var/log/supervisor

ADD id_rsa.pub ./

# http://www.linuxproblem.org/art_9.html
RUN mkdir /root/.ssh
RUN cat ./id_rsa.pub >> /root/.ssh/authorized_keys

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22

COPY entrypoint.sh /scripts/entrypoint.sh
COPY master-ossec.conf /scripts/master-ossec.conf
COPY worker-ossec.conf /scripts/worker-ossec.conf

# install dependencies
RUN apt-get update && apt-get install python git gnupg2 gcc make vim libc6-dev curl policycoreutils automake autoconf libtool apt-transport-https lsb-release python-cryptography sqlite3 -y && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# install Wazuh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout $wazuhbranch
# build Python dependencies
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

# wazuh-documentation dependencies
RUN /var/ossec/framework/python/bin/pip3 install Sphinx==1.6.5 sphinx-rtd-theme==0.2.4 sphinxcontrib-images==0.7.0 sphinxprettysearchresults==0.3.5

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest defusedxml ptvsd pydevd-pycharm~=191.6605.12 freezegun

# install and configure Wazuh API
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash - && apt-get install -y nodejs && npm config set user 0
RUN git clone https://github.com/wazuh/wazuh-api && cd /wazuh-api && git checkout $wazuhapibranch && ./install_api.sh && npm install mocha -g && npm install glob supertest mocha should moment

# install ZSH
RUN apt-get install zsh -y
RUN cd /root && sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

