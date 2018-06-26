#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
from utils import read_json_from_file

class User():

    def __init__(self, user_name, ossec_path):
        self.user_name = user_name
        self.role = Role(self._get_user_role(ossec_path), ossec_path)

    def __str__(self):
        return self.user_name

    def _get_user_role(self, ossec_path):
        roles_config = read_json_from_file(ossec_path + "/api/models/rbac/roles_config.json")
        role_user = [role for role, users in roles_config.items() if self.user_name in users]

        if not role_user:
            raise Exception("No role found for user `{}`".format(self.user_name))

        return role_user[0]

    def _get_request_method_and_controller(self, request_function):
        split_request = request_function.split("/")
        if not split_request or split_request < 2:
            return None, None

        request_method = split_request[0].replace(" ", "").upper() \
            if split_request[0] else "GET"
        request_controller = "/" + split_request[1]

        return request_method, request_controller

    def has_permission_to_exec(self, request):
        has_permission = False
        request_method, request_controller = self._get_request_method_and_controller(request['function'])

        if request_method and request_controller:
            permissions = self.role.permissions.get(request_controller)
            has_permission = request_method in permissions if permissions else True

        return has_permission