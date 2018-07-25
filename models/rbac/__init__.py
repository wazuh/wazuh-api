#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from rbac.role import _load_roles_mapping_from_file, _load_groups_mapping_from_file
from rbac.user import User, _load_users_mapping_from_file

from sys import path
from os import path as os_path
new_path = '/var/ossec/framework'
if not os_path.exists(new_path):
    current_path = path[0].split('/')
    new_path = "/{0}/{1}/framework".format(current_path[1], current_path[2])
path.append(new_path)

from wazuh.utils import cut_array, search_array, sort_array
from wazuh import common
from wazuh.exception import WazuhException

class Rbac():

    def __init__(self, ossec_path, realm='native'):
        self.ossec_path = ossec_path
        self.reserved_roles = {
            "superuser": {"/*": {"methods": ["GET", "POST", "PUT", "DELETE"]}},
            "app": {"/*": {"methods": ["GET", "POST", "PUT", "DELETE"]}}
        }

    def get_json_user_privileges(self, user_name):
        return User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_privileges()

    def get_json_user_roles(self, user_name):
        return User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_roles()

    def get_json_user_groups(self, user_name):
        return User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_groups()

    def get_json_user_info(self, user_name):
        groups = User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_groups()
        privileges = User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_privileges()
        roles = User(user_name=user_name, ossec_path=self.ossec_path).get_json_user_roles()

        return {"roles":roles["items"], "privileges":privileges["items"], "groups":groups["items"]}


    def _apply_filters_array(self, response, valid_select_fields, valid_search_fields, select={}, offset=0,
                             limit=common.database_limit, search={}, sort={}):
        offset = int(offset)
        limit = int(limit)

        if select:
            incorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            if incorrect_fields:
                raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(', '.join(valid_select_fields), ','.join(incorrect_fields)))
        else:
            select['fields'] = valid_select_fields

        if sort:
            if not set(sort.get('fields')).issubset(select.get('fields')):
                raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.
                                     format(valid_select_fields, sort['fields']))

        if select and select.get('fields'):
            filter_response = []
            for item in response['items']:
                filter_response.append({key:value for key,value in item.items() if key in select['fields']})
            response['items'] = filter_response

        if sort:
            response['items'] = sort_array(response['items'], sort['fields'], sort['order'])

        if search:
            response['items'] = search_array(response['items'], search['value'], search['negation'],
                                             fields=valid_search_fields)


        return {'items': cut_array(response['items'], offset, limit), 'totalItems': response['totalItems']}


    def get_json_all_roles(self, realm='native', select={}, offset=0, limit=common.database_limit, search={}, sort={}):
        roles =  _load_roles_mapping_from_file(self.ossec_path, realm, True)
        roles_list = [{"role":role,"privileges":resources} for role, resources in roles.items()]

        valid_select_fields = ['privileges', 'role']
        valid_search_fields = ['role']

        response =  self._apply_filters_array(response={"items":roles_list, "totalItems":len(roles_list)},
                                         valid_select_fields=valid_select_fields, valid_search_fields=valid_search_fields,
                                        select=select, offset=offset, limit=limit, search=search, sort=sort)
        return response

    def get_json_all_groups_from_file(self, select={}, offset=0, limit=common.database_limit, search={}, sort={}):
        groups_config = _load_groups_mapping_from_file(self.ossec_path)
        groups_list = [{"group":group,"users":group_data.get("users")} for group, group_data in groups_config.items()]

        valid_select_fields = ['group', 'users']
        valid_search_fields = ['group', 'users']

        response =  self._apply_filters_array(response={"items":groups_list, "totalItems":len(groups_list)},
                                         valid_select_fields=valid_select_fields, valid_search_fields=valid_search_fields,
                                        select=select, offset=offset, limit=limit, search=search, sort=sort)
        return response

    def get_json_all_user_info(self):
        roles_users = _load_users_mapping_from_file(self.ossec_path)
        users_info = {user:self.get_json_user_info(user) for users in roles_users.values() for user in users.get("users") }
        return users_info