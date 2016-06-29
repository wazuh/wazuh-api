#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from glob import glob
import xml.etree.ElementTree as ET
from wazuh.configuration import Configuration
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import cut_array

class Rule:
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'

    def __init__(self):
        self.file = None
        self.description = ""
        self.id = None
        self.level = None
        self.status = None
        self.groups = []
        self.pci = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Rule):
            return self.id < other.id
        else:
            raise WazuhException(1204)

    def __le__(self, other):
        if isinstance(other, Rule):
            return self.id <= other.id
        else:
            raise WazuhException(1204)

    def __gt__(self, other):
        if isinstance(other, Rule):
            return self.id > other.id
        else:
            raise WazuhException(1204)

    def __ge__(self, other):
        if isinstance(other, Rule):
            return self.id >= other.id
        else:
            raise WazuhException(1204)

    def to_dict(self):
        dictionary = {'file': self.file, 'id': self.id, 'level': self.level, 'description': self.description, 'status': self.status, 'groups': self.groups, 'pci': self.pci, 'details': self.details}
        return dictionary

    def set_group(self, group):
        Rule.__add_unique_element(self.groups, group)

    def set_pci(self, pci):
        Rule.__add_unique_element(self.pci, pci)

    def add_detail(self, detail, value):
        if detail in self.details:
            if type(self.details[detail]) is not list:
                element = self.details[detail]
                self.details[detail] = [element]

            self.details[detail].append(value)
        else:
            self.details[detail] = value

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
    def __check_status(status):
        if status is None:
            return Rule.S_ALL
        elif status in [Rule.S_ALL, Rule.S_ENABLED, Rule.S_DISABLED]:
            return status
        else:
            raise WazuhException(1202)

    @staticmethod
    def get_rules_files(status=None, offset=0, limit=0):
        data = []

        status = Rule.__check_status(status)

        # Enabled rules
        ossec_conf = Configuration().get_ossec_conf()

        if 'rules' in ossec_conf and 'include' in ossec_conf['rules']:
            data_enabled = ossec_conf['rules']['include']
        else:
            raise WazuhException(1200)

        if status == Rule.S_ENABLED:
            for f in data_enabled:
                data.append({'name': f, 'status': 'enabled'})
            return {'items': cut_array(sorted(data), offset, limit), 'totalItems': len(data)}

        # All rules
        data_all = []
        rule_paths = sorted(glob("{0}/*_rules.xml".format(common.rules_path)))
        for rule_path in rule_paths:
            data_all.append(rule_path.split('/')[-1])

        # Disabled
        for r in data_enabled:
            if r in data_all:
                data_all.remove(r)
        for f in data_all:  # data_all = disabled
            data.append({'name': f, 'status': 'disabled'})

        if status == Rule.S_DISABLED:
            return {'items': cut_array(sorted(data), offset, limit), 'totalItems': len(data)}
        if status == Rule.S_ALL:
            for f in data_enabled:
                data.append({'name': f, 'status': 'enabled'})

        return {'items': cut_array(sorted(data), offset, limit), 'totalItems': len(data)}

    @staticmethod
    def get_rules(status=None, group=None, pci=None, file=None, id=None, level=None, offset=0, limit=0):
        all_rules = []
        rules = []

        if level:
            levels = level.split('-')
            if len(levels) < 0 or len(levels) > 2:
                raise WazuhException(1203)

        for rule_file in Rule.get_rules_files(status)['items']:
            all_rules.extend(Rule.__load_rules_from_file(rule_file['name'], rule_file['status']))

        rules = list(all_rules)
        for r in all_rules:
            if group and group not in r.groups:
                rules.remove(r)
            elif pci and pci not in r.pci:
                rules.remove(r)
            elif file and file != r.file:
                rules.remove(r)
            elif id and int(id) != r.id :
                rules.remove(r)
            elif level:
                if len(levels) == 1:
                    if int(levels[0]) != r.level:
                        rules.remove(r)
                elif not (int(levels[0]) <= r.level <= int(levels[1])):
                        rules.remove(r)

        return {'items': cut_array(sorted(rules), offset, limit), 'totalItems': len(rules)}

    @staticmethod
    def get_groups(offset=0, limit=0):
        groups = set()

        for rule in Rule.get_rules()['items']:
            for group in rule.groups:
                groups.add(group)

        return {'items': cut_array(sorted(groups), offset, limit), 'totalItems': len(groups)}

    @staticmethod
    def get_pci(offset=0, limit=0):
        pci = set()

        for rule in Rule.get_rules()['items']:
            for pci_item in rule.pci:
                pci.add(pci_item)

        return {'items': cut_array(sorted(pci), offset, limit), 'totalItems': len(pci)}

    @staticmethod
    def __load_rules_from_file(rule_path, rule_status):
        try:
            rules = []
            # wrap the data
            f = open("{0}/{1}".format(common.rules_path, rule_path))
            data = f.read()
            data = data.replace(" -- ", " -INVALID_CHAR ")
            f.close()
            xmldata = '<root_tag>' + data + '</root_tag>'

            root = ET.fromstring(xmldata)
            for xml_group in root.getchildren():
                if xml_group.tag.lower() == "group":
                    general_groups = xml_group.attrib['name'].split(',')
                    for xml_rule in xml_group.getchildren():
                        # New rule
                        if xml_rule.tag.lower() == "rule":
                            groups = []
                            rule = Rule()
                            rule.file = rule_path
                            rule.id = int(xml_rule.attrib['id'])
                            rule.level = int(xml_rule.attrib['level'])
                            rule.status = rule_status

                            for k in xml_rule.attrib:
                                if k != 'id' and k != 'level':
                                    rule.details[k] = xml_rule.attrib[k]

                            for xml_rule_tags in xml_rule.getchildren():
                                tag = xml_rule_tags.tag.lower()
                                value = xml_rule_tags.text
                                if tag == "group":
                                    groups.extend(value.split(","))
                                elif tag== "description":
                                    rule.description += value
                                elif tag == "field":
                                    rule.add_detail(xml_rule_tags.attrib['name'], value)
                                else:
                                    rule.add_detail(tag, value)

                            # Set groups
                            groups.extend(general_groups)

                            pci_groups = []
                            ossec_groups = []
                            for g in groups:
                                if 'pci_' in g:
                                    pci_groups.append(g)
                                else:
                                    ossec_groups.append(g)

                            rule.set_group(ossec_groups)
                            rule.set_pci(pci_groups)


                            rules.append(rule)
        except Exception as e:
            raise WazuhException(1201, "{0}. Error: {1}".format(rule_path, str(e)))

        return rules
