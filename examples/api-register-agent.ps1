###
#  Powershell script for registering agents automatically with the API
#  Copyright (C) 2017 Wazuh, Inc. All rights reserved.
#  Wazuh.com
#
#  This program is a free software; you can redistribute it
#  and/or modify it under the terms of the GNU General Public
#  License (version 2) as published by the FSF - Free Software
#  Foundation.
###

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

function req($method, $resource, $params){
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $url = $base_url + $resource;

    try{
        return Invoke-WebRequest -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method $method -Uri $url -Body $params
    }catch{
        return $_.Exception
    }

}

# Configuration
$base_url = "http://10.0.0.1:55000"
$username = "foo"
$password = "bar"
$agent_name = $env:computername
$path = "C:\Program Files (x86)\ossec-agent\"
Ignore-SelfSignedCerts

# Adding agent and getting Id from manager

Write-Output "`r`nAdding agent:"
$response = req -method "POST" -resource "/agents" -params @{name=$agent_name} | ConvertFrom-Json
If ($response.error -ne '0') {
  Write-Output "ERROR: $($response.message)"
  Exit
}
$agent_id = $response.data
Write-Output "Agent '$($agent_name)' with ID '$($agent_id)' added."

# Getting agent key from manager

Write-Output "`r`nGetting agent key:"
$response = req -method "GET" -resource "/agents/$($agent_id)/key" | ConvertFrom-Json
If ($response.error -ne '0') {
  Write-Output "ERROR: $($response.message)"
  Exit
}
$agent_key = $response.data
Write-Output "Key for agent '$($agent_id)' received."

# Importing key

Write-Output "`r`nImporting authentication key:"
echo "y" | & "$($path)manage_agents.exe" "-i $($agent_key)" "y`r`n"

# Restarting agent

Write-Output "`r`nRestarting:"
$srvName = "OssecSvc"

Write-Output "Stopping service."
Stop-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"

Write-Output "Starting service."
Start-Service $srvName
$srvStat = Get-Service $srvName
Write-Output "$($srvName) is now $($srvStat.status)"
