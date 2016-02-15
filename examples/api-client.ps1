###
#  API RESTful for OSSEC
#  Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

# How to use OSSEC Wazuh RESTful API from PowerShell 3.0+
# Documentation: http://wazuh-documentation.readthedocs.org/en/latest/ossec_api.html

function req($method, $resource){
    # Config
    $base_url = "https://54.229.81.196:55000"
    $username = "foo"
    $password = "bar"

    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $url = $base_url + $resource;

    try{
        return Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method $method -Uri $url
    }catch{
        return $_.Exception
    }
    
}

Write-Output "Welcome:"
$response = req -method "get" -resource "/"
Write-Output $response

Write-Output "`r`n`r`nAgents:"
$response = req -method "get" -resource "/agents"
Write-Output $response

Write-Output "`r`n`r`nManager:"
$response = req -method "get" -resource "/manager/status"
Write-Output $response

Write-Output "`r`n`r`nWazuh.com"
