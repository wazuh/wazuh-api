#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

try:
    from subprocess import check_output
except ImportError:
    def check_output(arguments, stdin=None, stderr=None, shell=False):
        temp_f = mkstemp()
        returncode = call(arguments, stdin=stdin, stdout=temp_f[0], stderr=stderr, shell=shell)
        close(temp_f[0])
        file_o = open(temp_f[1], 'r')
        cmd_output = file_o.read()
        file_o.close()
        remove(temp_f[1])

        if returncode != 0:
            error_cmd = CalledProcessError(returncode, arguments[0])
            error_cmd.output = cmd_output
            raise error_cmd
        else:
            return cmd_output

def insert_row(fields, sizes, highlight=False):
    row = ''
    for i in range(len(fields)):
        if i == 0 and highlight:
            row += '| ``' + fields[i] + '``' + ' '*(sizes[i]-len(fields[i])-1-2-2)
        else:
            row += '| ' + fields[i] + ' '*(sizes[i]-len(fields[i])-1)
    row += '|' +'\n'

    return row

def insert_separator(sizes, sep='-'):
    row = ''
    for size in sizes:
        row += '+' + sep*size
    row += '+' +'\n'

    return row

def create_table(headers, rows, sizes):
    output = ''
    output += insert_separator(sizes)
    output += insert_row(headers, sizes)
    output += insert_separator(sizes, '=')
    for row in rows:
        fields = [row['field'], row['type'], row['description'].replace('<p>', '').replace('</p>', '')]
        output += insert_row(fields, sizes, not row['optional'])
        output += insert_separator(sizes)
    return output


if __name__ == "__main__":
    docu_file_json = './build/html/api_data.json'
    output = './build/ossec_api_reference.rst'
    f = open(output, 'w')
    f.write('.. _ossec_api_test:\n\n')

    try:
        with open(docu_file_json) as data_file:
            docu = json.load(data_file)
    except Exception as e:
        f.write("Error opening file '{0}': {1}".format(docu_file_json, e))

    # Group by section and subsection
    sections = {}
    request_list = {}

    for req in docu:
        ss = req['group']  # subsection
        if ss.startswith('_'):
            continue

        s = req['filename'].split('/')[-1][:-3]  # section

        if s not in sections:
            sections[s] = {}
            request_list[s] = []

        if ss in sections[s]:
            sections[s][ss].append(req)
        else:
            sections[s][ss] = [req]

        request_list[s].append(['{0} {1}'.format(req['type'].upper(), req['url']), req['title']])

    # Generate RST
    introduction = """Reference
======================
This API reference is organized by resources:

* `Agents`_
* `Manager`_
* `Rootcheck`_
* `Syscheck`_

Also, it is provided an `Request List`_ with all available requests.

"""
    f.write(introduction)

    f.write('\nRequest List\n')
    f.write('---------------------------------' + '\n\n')
    for req in sorted(request_list.keys()):
        f.write('`{0}`_\n'.format(req.title()))
        for item in sorted(request_list[req]):
            f.write('\t* {0}  (`{1}`_)\n'.format(item[0], item[1]))
        f.write('\n')

    for s in sorted(sections.keys()):
        f.write(s.title() + '\n')
        f.write('---------------------------------' + '\n')
        for ss in sorted(sections[s].keys()):
            f.write(ss + '\n')
            f.write('+++++++++++++++++++++++++\n\n')
            for item in sections[s][ss]:
                f.write(item['title'] + '\n')
                f.write('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~' + '\n')
                f.write(item['description'].replace('<p>', '').replace('</p>', '') + '\n')
                f.write('\n**Request**:\n\n')
                f.write('``{0}`` ::\n\n\t{1}\n'.format(item['type'].upper(), item['url']))
                print('\n{0} - {1}'.format(item['type'].upper(), item['url']))
                if 'parameter' in item:
                    rows = []
                    f.write('\n**Parameters**:\n\n')
                    params = item['parameter']['fields']['Parameter']
                    table = create_table(['Param', 'Type', 'Description'], params, [20, 15, 200])
                    f.write(table)
                f.write('\n')

                for example in item['examples']:
                    f.write('**Example Request:**' + '\n')
                    f.write('::\n')
                    f.write('\n\t{0}\n\n'.format(example['content']))

                    try:
                        command = []
                        for arg in example['content'].split(' '):
                            start = 0
                            end = len(arg)

                            if arg[0] == '\'' or arg[0] == '"':
                                start += 1
                            if arg[-1] == '\'' or arg[-1] == '"':
                                end -= 1

                            command.append(arg[start:end])

                        command.extend(['--connect-timeout', '5'])

                        output = check_output(command)
                    except Exception as e:
                        output = "Error: {0}".format(e)

                    f.write('**Example Response:**' + '\n')
                    f.write('::\n')
                    for line in output.split('\n'):
                        f.write('\n\t{0}'.format(line))
                f.write('\n')
            f.write('\n')
        f.write('\n')

f.close()
