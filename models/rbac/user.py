#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
from rbac.request import Request
from utils import read_json_from_file

class User():

    def __init__(self, user_name, ossec_path, realm='native'):
        self.user_name = user_name
        self._load_roles(ossec_path, realm)

    def _load_roles(self, ossec_path, realm):
        roles_user = self._get_user_roles_from_file(ossec_path)
        groups_user = self._get_user_groups_from_file(ossec_path)

        if not roles_user:
            raise Exception("No roles found for user `{}`".format(self.user_name))

        self.groups = [Role(group_name, ossec_path, realm) for group_name in groups_user]
        self.roles = [Role(role_name, ossec_path, realm) for role_name in roles_user]

    def __str__(self):
        return self.user_name

    def _get_user_groups_from_file(self, ossec_path):
        group_mapping = read_json_from_file(ossec_path + "/api/models/rbac/group_mapping.json")
        return [group for group, users in group_mapping.items() if self.user_name in users]

    def _get_user_roles_from_file(self, ossec_path):
        roles_config = read_json_from_file(ossec_path + "/api/models/rbac/roles_config.json")
        return [role for role, users in roles_config.items() if self.user_name in users]

    def _check_privileges_in_roles(self, request_method, request_resource):
        has_permission = False
        for role in self.roles:
            has_permission = role.can_exec(request_method, request_resource)
            if has_permission:
                break

        return has_permission

    def _check_privileges_in_groups(self, request_method, request_resource):
        has_permission = False
        for group in self.groups:
            has_permission = group.can_exec(request_method, request_resource)
            if has_permission:
                break

        return has_permission

    def _check_privileges(self, request_method, request_resource):
        has_permission = self._check_privileges_in_roles(request_method, request_resource) \
                            or self._check_privileges_in_groups(request_method, request_resource)
        return has_permission

    def has_permission_to_exec(self, request_param):
        request = Request(request_param)
        request_method = request.get_method()
        request_url= request._ignore_pretty(request.get_url())

        has_permission = self._check_privileges(request_method, request_url) \
            if request_method and request_url else False
        
        return has_permission

    def get_json_user_roles(self):
        return {"items":[str(role) for role in self.roles], "totalItems":len(self.roles)}

    def get_json_user_privileges(self):
        list_user_privileges = []
        privileges_added = []

        for role in self.roles:
            for privilege_key, privilege_value in role.get_privileges_json()['privileges'].items():
                if privilege_key in privileges_added:
                    for privilege in list_user_privileges:
                        if privilege["resource"] == privilege_key:
                            privilege["methods"] = privilege_value['methods'] + \
                            (list(set(privilege['methods']) - set(privilege_value['methods'])) )
                else:
                    privileges_added.append(privilege_key)
                    list_user_privileges.append({"resource":privilege_key,"methods":privilege_value["methods"]})

        return {'items':list_user_privileges, 'totalItems':len(list_user_privileges)}