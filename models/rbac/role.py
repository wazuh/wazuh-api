# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import read_json_from_file
from rbac.request import Request
import re

class Role():

    def __init__(self, role, ossec_path, realm="native"):
        self.role = role
        self._load_role_privileges_from_file(ossec_path, realm)

    def __str__(self):
        return self.role

    def _load_role_privileges_from_file(self, ossec_path, realm="native"):
        roles_mapping = read_json_from_file(ossec_path + "/api/models/rbac/roles_mapping.json")

        realms_mapping = roles_mapping.get('realms')
        if not realms_mapping:
            raise Exception("No mapping found for realms")

        current_realm_roles = realms_mapping.get(realm)
        if not current_realm_roles:
            raise Exception("No mapping found for realm `{}`".format(realm))

        self.privileges = current_realm_roles.get(self.role)
        if not self.privileges:
            raise Exception("No mapping found for role `{}`".format(self.role))

    def _parse_request(self, request):
        return Request(request)

    def _parse_role_url(self, url):
        url_parsed = url
        if "*" in url:
            url_parsed = url.replace('*', ".*")

        return url_parsed

    def can_exec(self, request):
        request = Request(request)
        request_method = request.get_method()
        request_url= request.get_url()

        can_exec_request = False
        for role_url, privileges_for_resource in self.privileges.items():

            # Check url
            role_url = self._parse_role_url(role_url)
            regex = re.compile(r'^' + role_url + '$')
            if not regex.match(request_url):
                continue

            # Check method
            can_exec_request = True if privileges_for_resource['methods'] == "*" \
                else request_method in privileges_for_resource['methods']
            if can_exec_request:
                break

        return can_exec_request

    def get_privileges_json(self):
        return {"privileges":self.privileges}
