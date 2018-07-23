# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import read_json_from_file
from rbac.request import Request
import re

reserved_roles = {
    "superuser": {"/*": {"methods": ["GET", "POST", "PUT", "DELETE"]}},
    "app": {"/*": {"methods": ["GET", "POST", "PUT", "DELETE"]}}
}

def _load_roles_mapping_from_file(ossec_path, realm='native', reserved_info=False):
    roles_mapping = read_json_from_file(ossec_path + "/api/models/rbac/roles_mapping.json")

    realms_mapping = roles_mapping.get('realms')
    if not realms_mapping:
        raise Exception("No mapping found for realms")

    current_realm_roles = realms_mapping.get(realm)
    if not current_realm_roles:
        raise Exception("No mapping found for realm `{}`".format(realm))

    if reserved_info:
        for role, data in reserved_roles.items():
            data.update({'reserved': True})

        for role, data in current_realm_roles.items():
            data.update({'reserved': False})

    roles = current_realm_roles
    roles.update(reserved_roles)
    return roles


class Role():

    def __init__(self, role, ossec_path, realm="native"):
        self.role = role
        self._load_role_privileges(ossec_path=ossec_path, realm=realm)

    def __str__(self):
        return self.role

    def _load_role_privileges(self, ossec_path, realm="native"):
        self.privileges = _load_roles_mapping_from_file(ossec_path=ossec_path, realm=realm).get(self.role)
        if not self.privileges:
            raise Exception("No mapping found for role `{}`".format(self.role))

    def _parse_role_url(self, url):
        url_parsed = url
        if "*" in url:
            url_parsed = url.replace('*', ".*")

        return url_parsed

    def _match_url_requests(self, resource_url, request_url):
        return re.compile(r'^' + self._parse_role_url(resource_url) + '$').match(request_url)

    def _check_role_exception(self, request_url, exception_list):
        is_exception = False
        for current_exception in exception_list:
            if self._match_url_requests(current_exception, request_url):
                is_exception = True
                break
        return is_exception

    def can_exec(self, request):
        request = Request(request)
        request_method = request.get_method()
        request_url= request.get_url()

        can_exec_request = False
        for role_url, privileges_for_resource in self.privileges.items():

            # Check url
            if not self._match_url_requests(role_url, request_url):
                continue

            # Check exceptions
            if 'exceptions' in privileges_for_resource and \
                    self._check_role_exception(request_url, privileges_for_resource['exceptions']):
                continue

            # Check method
            can_exec_request = True if privileges_for_resource['methods'] == "*" \
                else request_method in privileges_for_resource['methods']

            if can_exec_request:
                break

        return can_exec_request

    def get_privileges_json(self):
        return {"privileges":self.privileges}
