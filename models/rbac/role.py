# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json as json


class Role():

    def __init__(self, role, ossec_path):
        self.role = role
        self._load_role_permissions(ossec_path)

    def __str__(self):
        return self.role

    def _load_role_permissions(self, ossec_path):
        path = ossec_path + "/api/models/rbac/roles_mapping.json"
        with open(path) as f:
            roles_mapping = json.loads(f)

        self.permissions = roles_mapping[self.role]

