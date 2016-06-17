#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from glob import glob
import xml.etree.ElementTree as ET
from wazuh.configuration import Configuration
from wazuh.exception import WazuhException

__all__ = ["Rules", "Rule"]


class Rules:
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'

    def __init__(self, path='/var/ossec'):
        self.ossec_path = path
        self.path = '{0}/rules'.format(path)

    def __check_status(self, status):
        if status is None:
            return self.S_ALL
        elif status in [self.S_ALL, self.S_ENABLED, self.S_DISABLED]:
            return status
        else:
            raise WazuhException(1202)

    def get_rules(self, status=None):
        rules = []

        for rule_file in self.get_rules_files(status):
            rules.extend(self.__load_rules_from_file(rule_file['name'], rule_file['status']))

        return rules

    def get_rules_files(self, status=None):
        data = []

        status = self.__check_status(status)

        # Enabled rules
        ossec_conf = Configuration(self.ossec_path).get_ossec_conf()

        if 'rules' in ossec_conf and 'include' in ossec_conf['rules']:
            data_enabled = ossec_conf['rules']['include']
        else:
            raise WazuhException(1200)

        if status == self.S_ENABLED:
            for f in data_enabled:
                data.append({'name': f, 'status': 'enabled'})
            return sorted(data)

        # All rules
        data_all = []
        rule_paths = sorted(glob("{0}/*_rules.xml".format(self.path)))
        for rule_path in rule_paths:
            data_all.append(rule_path.split('/')[-1])

        # Disabled
        for r in data_enabled:
            if r in data_all:
                data_all.remove(r)
        for f in data_all:  # data_all = disabled
            data.append({'name': f, 'status': 'disabled'})

        if status == self.S_DISABLED:
            return sorted(data)
        if status == self.S_ALL:
            for f in data_enabled:
                data.append({'name': f, 'status': 'enabled'})

        return sorted(data)


    def get_rules_with_group(self, group, status=None):
        rules = []

        for r in self.get_rules(status):
            if group in r.groups:
                rules.append(r)

        return rules

    def get_rules_with_file(self, file, status=None):
        rules = []

        for r in self.get_rules(status):
            if file == r.file:
                rules.append(r)

        return rules

    def get_rules_with_level(self, level, status=None):
        rules = []

        levels = level.split('-')

        if 0 < len(levels) <= 2:

            for r in self.get_rules(status):
                if len(levels) == 1:
                    if levels[0] == r.level:
                        rules.append(r)
                elif levels[0] <= r.level <= levels[1]:
                        rules.append(r)
        else:
            raise WazuhException(1203)

        return rules

    def get_rule(self, id):
        rule = ""

        for r in self.get_rules():
            if r.id == str(id):
                rule = r
                break

        return rule

    def get_groups(self):
        groups = set()

        for rule in self.get_rules():
            for group in rule.groups:
                groups.add(group)

        return sorted(list(groups))

    def __load_rules_from_file(self, rule_path, rule_status):
        try:
            rules = []
            # wrap the data
            f = open("{0}/{1}".format(self.path, rule_path))
            data = f.read()
            f.close()
            xmldata = '<root_tag>' + data + '</root_tag>'

            root = ET.fromstring(xmldata)
            for xml_group in root.getchildren():
                if xml_group.tag.lower() == "group":
                    general_groups = xml_group.attrib['name'].split(',')
                    for xml_rule in xml_group.getchildren():
                        # New rule
                        if xml_rule.tag.lower() == "rule":
                            rule = Rule(rule_path)
                            rule.id = xml_rule.attrib['id']
                            rule.level = xml_rule.attrib['level']
                            rule.set_group(general_groups)
                            rule.status = rule_status

                            for k in xml_rule.attrib:
                                if k != 'id' and k != 'level':
                                    rule.details[k] = xml_rule.attrib[k]

                            for xml_rule_tags in xml_rule.getchildren():
                                if xml_rule_tags.tag.lower() == "group":
                                    rule.set_group(xml_rule_tags.text.split(","))
                                elif xml_rule_tags.tag.lower() == "description":
                                    rule.description = xml_rule_tags.text
                                elif xml_rule_tags.tag.lower() == "field":
                                    rule.details[xml_rule_tags.attrib['name']] = xml_rule_tags.text
                                else:
                                    rule.details[xml_rule_tags.tag.lower()] = xml_rule_tags.text
                            rules.append(rule)
        except Exception as e:
            raise WazuhException(1201, "{0}. Error: {1}".format(rule_path, str(e)))

        return rules


class Rule:
    def __init__(self, file_rule):
        self.file = file_rule
        self.description = None
        self.id = None
        self.level = None
        self.status = None
        self.groups = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'file': self.file, 'id': self.id, 'level': self.level, 'description': self.description, 'status': self.status, 'groups': self.groups, 'details': self.details}
        return dictionary

    def set_group(self, group):
        groups = []

        if type(group) in [list, tuple]:
            groups.extend(group)
        else:
            groups.append(group)

        for gr in groups:
            if gr is not None and gr != '':
                g = gr.strip()
                if g not in self.groups:
                    self.groups.append(g)
