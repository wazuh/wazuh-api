#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from glob import glob
import xml.etree.ElementTree as ET
import wazuh.configuration as configuration
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import cut_array, sort_array, search_array


class Decoder:
    SORT_FIELDS = ['file', 'full_path', 'name', 'position']

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
    def get_decoders_files(offset=0, limit=0, sort=None, search=None):
        data = []
        decoder_dirs = []
        decoder_files = []

        ossec_conf = configuration.get_ossec_conf()

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

        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, order=sort['order'])
        else:
            data = sort_array(data, order='asc')

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

    @staticmethod
    def get_decoders(file=None, name=None, parents=False, offset=0, limit=0, sort=None, search=None):
        all_decoders = []
        decoders = []

        for decoder_file in Decoder.get_decoders_files()['items']:
            all_decoders.extend(Decoder.__load_decoders_from_file(decoder_file))

        decoders = list(all_decoders)
        for d in all_decoders:
            if file and file not in d.file:
                decoders.remove(d)
            if name and name != d.name:
                decoders.remove(d)
            if parents and 'parent' in d.details:
                decoders.remove(d)

        if search:
            decoders = search_array(decoders, search['value'], search['negation'])

        if sort:
            decoders = sort_array(decoders, sort['fields'], sort['order'], Decoder.SORT_FIELDS)
        else:
            decoders = sort_array(decoders, ['file', 'position'], 'asc')

        return {'items': cut_array(decoders, offset, limit), 'totalItems': len(decoders)}

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
