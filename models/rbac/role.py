# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import read_json_from_file

class Role():

    def __init__(self, role, ossec_path):
        self.role = role
        self._load_role_permissions_from_file(ossec_path)

    def __str__(self):
        return self.role

    def _load_role_permissions_from_file(self, ossec_path):
        roles_mapping = read_json_from_file(ossec_path + "/api/models/rbac/roles_mapping.json")

        self.permissions = roles_mapping.get(self.role)
        if not self.permissions:
            raise Exception("No mapping found for role `{}`".format(self.role))