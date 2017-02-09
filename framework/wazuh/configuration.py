#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from xml.etree.ElementTree import fromstring
from wazuh.exception import WazuhException
from wazuh import common

conf_sections = {
    'active-response': { 'type': 'duplicate', 'list_options': [] },
    'command': { 'type': 'duplicate', 'list_options': [] },
    'agentless': { 'type': 'duplicate', 'list_options': [] },
    'localfile': { 'type': 'duplicate', 'list_options': [] },
    'remote': { 'type': 'duplicate', 'list_options': [] },
    'syslog_output': { 'type': 'duplicate', 'list_options': [] },

    'alerts': { 'type': 'simple', 'list_options': [] },
    'client': { 'type': 'simple', 'list_options': [] },
    'database_output': { 'type': 'simple', 'list_options': [] },
    'email_alerts': { 'type': 'simple', 'list_options': [] },
    'reports': { 'type': 'simple', 'list_options': [] },
    'global': {
        'type': 'simple',
        'list_options': ['white_list']
    },

    'open-scap': {
        'type': 'mix',
        'list_options': ['content']
    },
    'rootcheck': {
        'type': 'mix',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps', 'windows_malware']
    },
    'ruleset': {
        'type': 'mix',
        'list_options':  ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir', 'list', 'rule_exclude', 'decoder_exclude']
    },
    'syscheck': {
        'type': 'mix',
        'list_options': ['directories', 'ignore', 'nodiff']
    }
}


def _insert(json, section_name, key, value):
    if not value:
        return

    if key in json:
        old_value = json[key]
        # The old value is a list -> append new value
        if type(old_value) is list:
            json[key].append(value)
        # The old value is simple -> update
        else:
            json[key] = value
    else:
        # if key in list_options -> store as list
        if section_name in conf_sections and key in conf_sections[section_name]['list_options']:
            json[key] = [value]
        else:
            json[key] = value


def _insert_section(json, section_name, section_json):
    # Duplicated sections -> always list
    if section_name in conf_sections and conf_sections[section_name]['type'] == 'duplicate':
        if section_name in json:
            json[section_name].append(section_json)
        else:
            json[section_name] = [section_json]
    # Mix sections:
    #   - If value in list_options -> append
    #   - else update value (final result: last value)
    elif section_name in conf_sections and conf_sections[section_name]['type'] == 'mix':
        if section_name in json:
            old_json = json[section_name]
            for value in section_json:
                if value in conf_sections[section_name]['list_options']:
                    old_json[value].extend(section_json[value])
                else:
                    old_json[value] = section_json[value]
            json[section_name] = old_json
        else:
            json[section_name] = section_json
    # Simple section: Update values and copy new ones
    else:
        if section_name in json:
            old_json = json[section_name]
            for value in section_json:
                old_json[value] = section_json[value]
            json[section_name] = old_json
        else:
            json[section_name] = section_json

def _read_option(section, opt):
    opt_name = opt.tag.lower()

    if section == 'open-scap':
        if opt.attrib:
            opt_value = {}
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
            # profiles
            profiles_list = []
            for profiles in opt.getchildren():
                profiles_list.append(profiles.text)

            if profiles_list:
                opt_value['profiles'] = profiles_list
        else:
            opt_value = opt.text
    elif section == 'syscheck' and opt_name == 'directories':
        opt_value = []

        json_attribs = {}
        for a in opt.attrib:
            json_attribs[a] = opt.attrib[a]

        for path in opt.text.split(','):
            json_path = {}
            json_path = json_attribs.copy()
            json_path['path'] = path.strip()
            opt_value.append(json_path)
    else:
        if opt.attrib:
            opt_value = {}
            opt_value['item'] = opt.text
            for a in opt.attrib:
                opt_value[a] = opt.attrib[a]
        else:
            opt_value = opt.text

    return opt_name, opt_value

def _conf2json(xml_conf):
    root_json = {}

    for root in xml_conf.getchildren():
        if root.tag.lower() == "ossec_config":
            for section in root.getchildren():
                section_name = 'open-scap' if section.tag.lower() == 'wodle' else section.tag.lower()
                section_json = {}

                for option in section.getchildren():
                    option_name, option_value = _read_option(section_name, option)
                    if type(option_value) is list:
                        for ov in option_value:
                            _insert(section_json, section_name, option_name, ov)
                    else:
                        _insert(section_json, section_name, option_name, option_value)

                _insert_section(root_json, section_name, section_json)

    return root_json


def get_ossec_conf(section=None, field=None):
    """
    Returns ossec.conf as dictionary.

    :param section: Filters by section (i.e. rules).
    :param field: Filters by field in section (i.e. included).
    :return: ossec.conf as dictionary.
    """

    try:
        # wrap the data
        f = open(common.ossec_conf)
        txt_data = f.read()
        txt_data = txt_data.replace(" -- ", " -INVALID_CHAR ")
        f.close()
        txt_data = '<root_tag>' + txt_data + '</root_tag>'

        # Read XML
        xml_data = fromstring(txt_data)

        # Parse XML to JSON
        data = _conf2json(xml_data)
    except:
        raise WazuhException(1101)

    if section:
        try:
            data = data[section]
        except:
            raise WazuhException(1102)

    if section and field:
        try:
            data = data[field]  # data[section][field]
        except:
            raise WazuhException(1103)

    return data
