# !/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

class Request():

    def __init__(self, request):
        self.request = request

    def get_method(self):
        split_request_function = self.request['function'].split("/", 1)
        if not split_request_function:
            return None

        request_method = split_request_function[0].upper() if split_request_function[0] else "GET"
        return request_method

    def get_resource(self):
        split_request_function = self.request['function'].split("/", 1)
        if not split_request_function or split_request_function < 2:
            return None

        request_resource = "/" + split_request_function[1]
        return request_resource

    def _ignore_pretty(self, url):
        if "?pretty" in url:
            url = url.replace("?pretty", "")
        elif "&pretty" in url:
            url = url.replace("&pretty", "")
        return url

    def get_url(self, ignore_pretty=True):
        return self.request['url'] if not ignore_pretty else self._ignore_pretty(self.request['url'])