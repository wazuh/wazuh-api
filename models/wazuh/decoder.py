#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from glob import glob
import xml.etree.ElementTree as ET
from wazuh.configuration import Configuration
from wazuh.exception import WazuhException
from wazuh import common


class Decoder:

    def __init__(self):
        self.file = None
        self.full_path = None
        self.name = None
        self.position = None
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'file': self.file, 'full_path': self.full_path, 'name': self.name, 'position': self.position, 'details': self.details}
        return dictionary

    def add_detail(self, detail, value):
        if detail in self.details:
            if type(self.details[detail]) is not list:
                element = self.details[detail]
                self.details[detail] = [element]

            self.details[detail].append(value)
        else:
            self.details[detail] = value

    @staticmethod
    def get_decoders():
        decoders = []

        for decoder_file in Decoder.get_decoders_files():
            decoders.extend(Decoder.__load_decoders_from_file(decoder_file))

        return decoders

    @staticmethod
    def get_decoders_files():
        data = []
        decoder_dirs = []
        decoder_files = []

        ossec_conf = Configuration().get_ossec_conf()

        if 'rules' in ossec_conf:
            if 'decoder_dir' in ossec_conf['rules']:
                decoder_dirs.extend(ossec_conf['rules']['decoder_dir'])
            if 'decoder' in ossec_conf['rules']:
                decoder_files.append(ossec_conf['rules']['decoder'])
        else:
            raise WazuhException(1500)

        for decoder_dir in decoder_dirs:
            path = "{0}/{1}/*_decoders.xml".format(common.ossec_path, decoder_dir)
            data.extend(glob(path))

        for decoder_file in decoder_files:
            data.append("{0}/{1}".format(common.ossec_path, decoder_file))

        return sorted(data)

    @staticmethod
    def get_decoders_by_file(file):
        decoders = []

        for decoder in Decoder.get_decoders():
            if decoder.file == file:
                decoders.append(decoder)

        return decoders

    @staticmethod
    def get_parent_decoders():
        decoders = []

        for decoder in Decoder.get_decoders():
            if 'parent' not in decoder.details:
                decoders.append(decoder)

        return decoders

    @staticmethod
    def get_decoders_by_name(name):
        decoders = []

        for decoder in Decoder.get_decoders():
            if decoder.name == name:
                decoders.append(decoder)

        return decoders


    @staticmethod
    def __load_decoders_from_file(decoder_path):
        try:
            decoders = []
            position = 0

            # wrap the data
            f = open(decoder_path)
            data = f.read()
            data = data.replace(" -- ", " -INVALID_CHAR ").replace("\<;", "\INVALID_CHAR;")
            f.close()
            xmldata = '<root_tag>' + data + '</root_tag>'

            root = ET.fromstring(xmldata)
            for xml_decoder in root.getchildren():
                # New decoder
                if xml_decoder.tag.lower() == "decoder":
                    decoder = Decoder()
                    decoder.full_path = decoder_path
                    decoder.file = decoder_path.split('/')[-1]
                    decoder.name = xml_decoder.attrib['name']
                    decoder.position = position
                    position += 1

                    for k in xml_decoder.attrib:
                        if k != 'name':
                            decoder.details[k] = xml_decoder.attrib[k]

                    for xml_decoder_tags in xml_decoder.getchildren():
                        decoder.add_detail(xml_decoder_tags.tag.lower(), xml_decoder_tags.text)

                    decoders.append(decoder)
        except Exception as e:
            raise WazuhException(1501, "{0}. Error: {1}".format(decoder_path, str(e)))

        return decoders
