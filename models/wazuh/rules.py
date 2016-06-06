#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Rules

from glob import glob
import xml.etree.ElementTree as ET
from wazuh.configuration import Configuration
from wazuh.exception import WazuhException


__all__ = ["Rules", "Rule"]


class Rules:

    def __init__(self, path='/var/ossec'):
        self.ossec_path = path
        self.path = '{0}/rules'.format(path)

    def get_rules(self, enabled=True):
        rules = []

        for filename_r in self.get_rules_files(enabled):
            rules.extend(self.__load_rules_from_file(filename_r))

        return rules

    def get_rules_files(self, enabled=True):
        if enabled:
            ossec_conf = Configuration(self.ossec_path).get_ossec_conf()

            if 'rules' in ossec_conf and 'include' in ossec_conf['rules']:
                data = ossec_conf['rules']['include']
            else:
                raise WazuhException(1200)
        else:
            data = []
            rule_paths = sorted(glob("{0}/*_rules.xml".format(self.path)))
            for rule_path in rule_paths:
                data.append(rule_path.split('/')[-1])

        return data

    def get_rules_with_group(self, group, enabled=True):
        rules = []

        for r in self.get_rules(enabled):
            if group in r.groups:
                rules.append(r)

        return rules

    def get_rule(self, id):
        rule = ""

        for r in self.get_rules(False):
            if r.id == str(id):
                rule = r
                break

        return rule

    def get_groups(self):
        # Get all rules
        groups = set()

        for rule in self.get_rules(False):
            for group in rule.groups:
                groups.add(group)

        return sorted(list(groups))

    def __load_rules_from_file(self, rule_path):
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
                        if xml_rule.tag.lower() == "rule":
                            rule = Rule(rule_path)
                            rule.id = xml_rule.attrib['id']
                            rule.level = xml_rule.attrib['level']
                            rule.set_group(general_groups)

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
            raise WazuhException(1201, rule_path)

        return rules


class Rule:
    def __init__(self, file_rule):
        self.file = file_rule
        self.description = None
        self.id = None
        self.level = None
        self.groups = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'file': self.file, 'id': self.id, 'level': self.level, 'description': self.description, 'groups': self.groups, 'details': self.details}
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
