#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import read_json_from_file
from rbac.user import User

class Rbac():

    def __init__(self, ossec_path):
        self.ossec_path = ossec_path

    def get_json_all_roles_from_file(self):
        roles_config = read_json_from_file(self.ossec_path + "/api/models/rbac/roles_config.json")
        roles = [role for role in roles_config.keys()]
        return {"roles": roles, "totalRoles":len(roles)}

    def get_json_user_privileges(self, user_name):
        user = User(user_name=user_name, ossec_path=self.ossec_path)
        roles = user.roles
        user_privileges = {}
        for role in roles:
            for privilege_key, privilege_value in role.get_privileges_json()['privileges'].items():
                if user_privileges.get(privilege_key):
                    user_privileges[privilege_key]['methods'] = user_privileges[privilege_key]['methods'] + \
                            (list(set(privilege_value['methods']) - set(user_privileges[privilege_key]['methods'])) )
                else:
                    user_privileges[privilege_key] = privilege_value

        return user_privileges

    def get_json_user_roles(self, user_name):
        user = User(user_name=user_name, ossec_path=self.ossec_path)
        return user.get_user_roles_json()
