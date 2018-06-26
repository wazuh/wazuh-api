#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
from utils import read_json_from_file

class User():

    def __init__(self, user_name, ossec_path):
        self.user_name = user_name
        self._load_user_roles_from_file(ossec_path)

    def __str__(self):
        return self.user_name

    def _load_user_roles_from_file(self, ossec_path):
        roles_config = read_json_from_file(ossec_path + "/api/models/rbac/roles_config.json")

        roles_user = [role for role, users in roles_config.items() if self.user_name in users]
        if not roles_user:
            raise Exception("No roles found for user `{}`".format(self.user_name))

        self.roles = [Role(role_name, ossec_path) for role_name in roles_user]

    def _get_method_from_request(self, request):
        split_request_function = request['function'].split("/", 1)
        if not split_request_function:
            return None

        request_method = split_request_function[0].upper() if split_request_function[0] else "GET"
        return request_method

    def _get_resource_from_request(self, request):
        split_request_function = request['function'].split("/", 1)
        if not split_request_function or split_request_function < 2:
            return None

        request_resource = "/" + split_request_function[1]
        return request_resource


    def _check_permissions_in_roles(self, request_method, request_resource):
        has_permission = False
        for role in self.roles:
            has_permission = role.can_exec(request_method, request_resource)
            if has_permission:
                break

        return has_permission

    def has_permission_to_exec(self, request):
        request_method = self._get_method_from_request(request)
        request_resource = self._get_resource_from_request(request)

        has_permission = self._check_permissions_in_roles(request_method, request_resource) \
            if request_method and request_resource else False

        return has_permission