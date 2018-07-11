#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
from rbac.request import Request
from utils import read_json_from_file

class User():

    def __init__(self, user_name, ossec_path, realm='native'):
        self.user_name = user_name
        self._load_user_roles_from_file(ossec_path, realm)

    def __str__(self):
        return self.user_name

    def _load_user_roles_from_file(self, ossec_path, realm):
        roles_config = read_json_from_file(ossec_path + "/api/models/rbac/roles_config.json")

        roles_user = [role for role, users in roles_config.items() if self.user_name in users]
        if not roles_user:
            raise Exception("No roles found for user `{}`".format(self.user_name))

        self.roles = [Role(role_name, ossec_path, realm) for role_name in roles_user]

    def _check_privileges_in_roles(self, request_method, request_resource):
        has_permission = False
        for role in self.roles:
            has_permission = role.can_exec(request_method, request_resource)
            if has_permission:
                break

        return has_permission

    def has_permission_to_exec(self, request_param):
        request = Request(request_param)
        request_method = request.get_method()
        request_url= request.get_url()

        has_permission = self._check_privileges_in_roles(request_method, request_url) \
            if request_method and request_url else False

        return has_permission

    def get_user_roles_json(self):
        return {"roles":[str(role) for role in self.roles], "totalRoles":len(self.roles)}