#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Stats

from wazuh.exception import WazuhException


__all__ = ["Stats"]


class Stats:
    DAYS = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"

    MONTHS = "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", \
             "Nov", "Dec"

    def __init__(self, path='/var/ossec'):
        self.ossec_path = path
        self.path = '{0}/stats'.format(path)

    def totals(self, year, month, day):
        '''
        Returns the totals file in JSON-exportable format
        year:   Year in YYYY format, e.g. 2016
        month:  Month in number or 3 first letters, e.g. Feb or 2
        day:    Day, e.g. 9
        '''

        try:
            year = int(year)
            day = int(day)

            if year < 0 or day < 0 or day > 31:
                raise WazuhException(1307)

            day = "%02d" % day
        except ValueError:
            raise WazuhException(1307)

        if month not in self.MONTHS:
            try:
                index = int(month)
            except ValueError:
                raise WazuhException(1307)

            if index < 1 or index > 12:
                raise WazuhException(1307)

            try:
                month = self.MONTHS[index-1]
            except IndexError:
                raise WazuhException(1307)

        try:
            stats = open(self.path + "/totals/" + str(year) + '/' + month + \
                        "/ossec-totals-" + day + ".log", 'r')
        except IOError:
            raise WazuhException(1308)

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
                        raise WazuhException(1309)

                hour = int(data[0])
                totalAlerts = int(data[1])
                events = int(data[2])
                syscheck = int(data[3])
                firewall = int(data[4])

                response.append({'hour': hour, 'alerts': alerts, \
                                 'totalAlerts': totalAlerts, 'events': events, \
                                 'syscheck': syscheck, 'firewall': firewall})
                alerts = []

        return response

    def hourly(self):
        '''Returns the hourly averages in JSON-exportable format'''

        averages = []
        interactions = 0

        # What's the 24 for?
        for i in range(25):
            try:
                hfile = open(self.path + '/hourly-average/' + str(i))
                data = hfile.read()

                if i == 24:
                    interactions = int(data)
                else:
                    averages.append(int(data))

                hfile.close()
            except IOError:
                if i < 24:
                    averages.append(0)

        return {'averages': averages, 'interactions': interactions}

    def weekly(self):
        '''Returns the weekly averages in JSON-exportable format'''

        response = {}

        # 0..6 => Sunday..Saturday
        for i in range(7):
            hours = []
            interactions = 0

            for j in range(25):
                try:
                    wfile = open(self.path + '/weekly-average/' + str(i) + '/' + str(j))
                    data = wfile.read()

                    if j == 24:
                        interactions = int(data)
                    else:
                        hours.append(int(data))

                    wfile.close()
                except IOError:
                    if i < 24:
                        hours.append(0)

            response[self.DAYS[i]] = {'hours': hours, 'interactions': interactions}

        return response
