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
        'type': 'simple',
        'list_options': ['content']
    },
    'rootcheck': {
        'type': 'simple',
        'list_options': ['rootkit_files', 'rootkit_trojans', 'windows_audit', 'system_audit', 'windows_apps', 'windows_malware']
    },
    'ruleset': {
        'type': 'simple',
        'list_options':  ['include', 'rule', 'rule_dir', 'decoder', 'decoder_dir', 'list', 'rule_exclude', 'decoder_exclude']
    },
    'syscheck': {
        'type': 'simple',
        'list_options': ['directories', 'ignore', 'nodiff']
    }
}


def _insert(json_dst, section_name, option, value):
    """
    Inserts element (option:value) in a section (json_dst) called section_name
    """

    if not value:
        return

    if option in json_dst:
        if type(json_dst[option]) is list:
            json_dst[option].append(value)  # Append new values
        else:
            json_dst[option] = value  # Update values
    else:
        if section_name in conf_sections and option in conf_sections[section_name]['list_options']:
            json_dst[option] = [value]  # Create as list
        else:
            json_dst[option] = value  # Update values


def _insert_section(json_dst, section_name, section_data):
    """
    Inserts a new section (section_data) called section_name in json_dst.
    """

    if section_name in conf_sections and conf_sections[section_name]['type'] == 'duplicate':
        if section_name in json_dst:
            json_dst[section_name].append(section_data)  # Append new values
        else:
            json_dst[section_name] = [section_data]  # Create as list
    elif section_name in conf_sections and conf_sections[section_name]['type'] == 'simple':
        if section_name in json_dst:
            for option in section_data:
                if option in json_dst[section_name] and option in conf_sections[section_name]['list_options']:
                    json_dst[section_name][option].extend(section_data[option])  # Append new values
                else:
                    json_dst[section_name][option] = section_data[option]  # Update values
        else:
            json_dst[section_name] = section_data  # Create


def _read_option(section_name, opt):
    """
    Reads an option (inside a section) and returns the name and the value.
    """

    opt_name = opt.tag.lower()

    if section_name == 'open-scap':
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
    elif section_name == 'syscheck' and opt_name == 'directories':
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
    """
    Returns a dict from a xml string.
    """
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
