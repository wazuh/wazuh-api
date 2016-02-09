#!/usr/bin/python

# Copyright (C) 2016 Wazuh Inc.

# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Totals: stats.py -t -y <year> -m <month> -d <day>
#   year:   Year in YYYY format, e.g. 2016
#   month:  Month in number or 3 first letters, e.g. Feb or 2
#   day:    Day, e.g. 9
# Hourly average: stats.py -h
# Weekly average: stats.py -w

from getopt import getopt, GetoptError
from sys import argv, exit
from os import getuid
from json import dumps

STATSDIR = "/var/ossec/stats"

DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"

MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", \
         "Nov", "Dec"

ERRORS = {1: {"error": 60, "description": "Invalid parameters"}, \
          2: {"error": 61, "description": "Couldn't open stats file"}, \
          3: {"error": 62, "description": "Statistics file damaged"}, \
          4: {"error": 63, "description": "Bad given arguments"}, \
          5: {"error": 64, "description": "Low permissions"} }

def usage():
    '''Prints help message'''
    print('''
Query statistical data from OSSEC-Wazuh in JSON format.

stats.py -t -y <year> -m <month> -d <day>
    Query totals file.
    year:   Year in YYYY format, e.g. 2016
    month:  Month in number or 3 first letters, e.g. Feb or 2
    day:    Day, e.g. 9
stats.py -h
    Print hourly averages.
stats.py -w
    Print weekly-hourly averages.
''')

def totals(year, month, day):
    '''Returns the totals file in JSON-exportable format'''

    try:
        year = int(year)
        day = int(day)

        if year < 0 or day < 0 or day > 31:
            return ERRORS[1]

        day = "%02d" % day
    except ValueError:
        return ERRORS[1]

    if month not in MONTHS:
        try:
            index = int(month)
        except ValueError:
            return ERRORS[1]

        if index < 1 or index > 12:
            return ERRORS[1]

        try:
            month = MONTHS[index-1]
        except IndexError:
            return ERRORS[1]

    try:
        stats = open(STATSDIR + "/totals/" + str(year) + '/' + month + \
                    "/ossec-totals-" + day + ".log", 'r')
    except IOError:
        return ERRORS[2]

    response = []
    alerts = []

    for line in stats:
        data = line.split('-')

        if len(data) == 4:
            hour = int(data[0])
            sigid = int(data[1])
            level = int(data[2])
            times = int(data[3])

            alert = {'sigid': sigid, 'level': level, 'times': times}
            alerts.append(alert)
        else:
            data = line.split('--')

            if len(data) != 5:
                if len(data) in (0, 1):
                    continue
                else:
                    return ERRORS[3]

            hour = int(data[0])
            totalAlerts = int(data[1])
            events = int(data[2])
            syscheck = int(data[3])
            firewall = int(data[4])

            response.append({'hour': hour, 'alerts': alerts, \
                             'totalAlerts': totalAlerts, 'events': events, \
                             'syscheck': syscheck, 'firewall': firewall})
            alerts = []

    return {'error': 0, 'response': response}

def hourly():
    '''Returns the hourly averages in JSON-exportable format'''

    averages = []
    interactions = 0

    # What's the 24 for?
    for i in range(25):
        try:
            hfile = open(STATSDIR + '/hourly-average/' + str(i))
            data = hfile.read()

            if i == 24:
                interactions = int(data)
            else:
                averages.append(int(data))

            hfile.close()
        except IOError:
            if i < 24:
                averages.append(0)

    return {'error': 0, 'response': {'averages': averages, \
            'interactions': interactions}}

def weekly():
    '''Returns the weekly averages in JSON-exportable format'''

    response = {}

    # 0..6 => Sunday..Saturday
    for i in range(7):
        hours = []
        interactions = 0

        for j in range(25):
            try:
                wfile = open(STATSDIR + '/weekly-average/' + str(i) + '/' + str(j))
                data = wfile.read()

                if j == 24:
                    interactions = int(data)
                else:
                    hours.append(int(data))

                wfile.close()
            except IOError:
                if i < 24:
                    hours.append(0)

        response[DAYS[i]] = {'hours': hours, 'interactions': interactions}

    return {'error': 0, 'response': response}

# Main section

if __name__ == '__main__':
    if getuid() != 0:
        print(dumps(ERRORS[5]))
        exit()

    try:
        options, args = getopt(argv[1:], "ty:m:d:wh")
    except GetoptError:
        usage()
        exit()

    for (option, value) in options:
        if option == '-t':
            query = 'totals'
        elif option == '-y':
            year = value
        elif option == '-m':
            month = value
        elif option == '-d':
            day = value
        elif option == '-h':
            query = 'hourly'
        elif option == '-w':
            query = 'weekly'
        else:
            usage();
            exit()

    if 'query' not in locals():
        output = ERRORS[4]
    elif query == 'totals':
        if 'year' not in locals() or 'month' not in locals() or 'day' not in locals():
            output = ERRORS[4]
        else:
            output = totals(year, month, day)
    elif query == 'hourly':
        output = hourly()
    elif query == 'weekly':
        output = weekly()
    else:
        output = ERRORS[4]

    print(dumps(output))
