#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
import json as json

class User():

    def __init__(self, user_name, ossec_path):
        self.user_name = user_name
        self.role = Role(self._get_user_role(ossec_path), ossec_path)

    def __str__(self):
        return self.user_name

    def _get_user_role(self, ossec_path):
        path = ossec_path + "/api/models/rbac/roles_config.json"
        with open(path) as f:
            roles_config = json.loads(f.read())

        role_user = [role for role, users in roles_config.items() if self.user_name in users][0]
        return role_user

    def _get_request_method_and_controller(self, request_function):
        split_request = request_function.split("/")
        if not split_request or split_request < 2:
            return None, None

        request_method_filtered = split_request[0].replace(" ", "").upper() \
            if split_request[0] else "GET"
        request_controller = "/" + split_request[1]

        return request_method_filtered, request_controller

    def has_permission_to_exec(self, request):
        request_method, request_controller = self._get_request_method_and_controller(request['function'])
        has_permission = request_method in self.role.permissions[request_controller] \
            if request_method and request_controller else False
        return has_permission

    def get_valid_methods(self):
        return self.role.permissions