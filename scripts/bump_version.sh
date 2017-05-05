#!/bin/bash

# Bump source version
# Wazuh Inc.

# Syntax:
# bump_version [ <version> ] [ -r <revision> ]
# Example:
# ./bump_version.sh v3.0.0-alpha1 -r 1000

version=$1
revision=$2

if [ -z "$version" ] && [ -z "$revision" ]
then
    echo "Error: no arguments given."
    echo "Syntax: $0 [ <version> ] [ -r <revision> ]"
    exit 1
fi

cd $(dirname $0)

PACKAGE_FILE="../package.json"
APP_FILE="../app.js"

if [ -n "$version" ]
then
    grep "\"version\":" $PACKAGE_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable version definition found at file $PACKAGE_FILE"
        exit 1
    fi

    sed -E -i "s/\"version\": \".+\",/\"version\": \"$version\",/g" $PACKAGE_FILE


    grep "current_version =" $APP_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable version definition found at file $APP_FILE"
        exit 1
    fi

    sed -E -i "s/current_version = \".+\";/current_version = \"v$version\";/g" $APP_FILE
fi

if [ -n "$revision" ]
then
    grep "\"revision\":" $PACKAGE_FILE > /dev/null

    if [ $? != 0 ]
    then
        echo "Error: no suitable revision definition found at file $PACKAGE_FILE"
        exit 1
    fi

    sed -E -i "s/\"revision\": \".+\",/\"revision\": \"$revision\",/g" $PACKAGE_FILE
fi
