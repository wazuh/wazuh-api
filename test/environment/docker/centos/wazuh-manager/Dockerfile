FROM centos:7

ARG wazuh_branch
ARG wazuh_api_branch
ARG wazuh_doc_branch

# enable SSH
RUN yum install openssl openssh-server -y
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN echo 'root:wazuh_admin' | chpasswd
RUN ssh-keygen -A

EXPOSE 22

# install dependencies
RUN yum install make gcc policycoreutils-python automake autoconf libtool epel-release git which -y

# install Python 3
RUN yum install python36 python36-pip -y

# install Wazuh
RUN git clone https://github.com/wazuh/wazuh && cd /wazuh && git checkout ${wazuh_branch}
# build Python dependencies
RUN sed -i 's!--index-url=file://${ROUTE_PATH}/${EXTERNAL_CPYTHON}/Dependencies/simple!!' /wazuh/src/Makefile
COPY preloaded-vars.conf /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh

# wazuh-documentation and dependencies
RUN git clone https://github.com/wazuh/wazuh-documentation && cd /wazuh-documentation && git checkout ${wazuh_doc_branch}
RUN pip3 install Sphinx==1.6.5 sphinx-rtd-theme==0.2.4 sphinxcontrib-images==0.7.0 sphinxprettysearchresults==0.3.5

# install pip libraries for development
RUN /var/ossec/framework/python/bin/pip3 install pytest defusedxml ptvsd pydevd-pycharm~=191.6605.12 freezegun

# install and configure Wazuh API
RUN curl --silent --location https://rpm.nodesource.com/setup_12.x | bash - && yum -y install nodejs && npm config set user 0
RUN git clone https://github.com/wazuh/wazuh-api && cd /wazuh-api && git checkout ${wazuh_api_branch} && ./install_api.sh && npm install mocha apidoc -g && npm install glob supertest mocha should moment mochawesome

# install ZSH
RUN yum install zsh -y
RUN cd /root && sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

# copy script for running mocha tests
COPY run_mocha_tests.sh /wazuh-api

# copy script for generating Wazuh API reference
COPY generate_api_doc.sh /wazuh-api/doc/generate_api_doc.sh

# copy entrypoint and configuration files
COPY entrypoint.sh /scripts/entrypoint.sh
COPY master-ossec.conf /scripts/master-ossec.conf
COPY worker-ossec.conf /scripts/worker-ossec.conf
