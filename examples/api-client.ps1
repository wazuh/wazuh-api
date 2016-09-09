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

###

# How to use OSSEC Wazuh RESTful API from PowerShell 3.0+
# Documentation: http://wazuh-documentation.readthedocs.org/en/latest/ossec_api.html

function Ignore-SelfSignedCerts {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
    
        public class PolicyCert : ICertificatePolicy {
            public PolicyCert() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert 
}

function req($method, $resource){
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $url = $base_url + $resource;

    try{
        return Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method $method -Uri $url
    }catch{
        return $_.Exception
    }
    
}

# Configuration
$base_url = "https://IP:55000"
$username = "foo"
$password = "bar"
Ignore-SelfSignedCerts

#Requests
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
