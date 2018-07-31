# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import Role
from utils import read_json_from_file

class Group():

    def __init__(self, group, ossec_path, realm="native"):
        self.group_name = group
        self._load_roles(ossec_path=ossec_path, realm=realm)

    def __str__(self):
        return self.group_name

    def _get_user_roles_from_file(self, ossec_path):
        roles_config = read_json_from_file(ossec_path + "/api/models/rbac/roles_config.json")
        return [role for role, role_data in roles_config.items() if role_data.get("groups") and self.group_name in role_data["groups"]]

    def _load_roles(self, ossec_path, realm):
        roles = self._get_user_roles_from_file(ossec_path=ossec_path)
        self.roles = [Role(role=role_name, ossec_path=ossec_path, realm=realm) for role_name in roles]

    def can_exec(self, request):
        has_permission = False
        for role in self.roles:
            has_permission = role.can_exec(request)
            if has_permission:
                break

        return has_permission