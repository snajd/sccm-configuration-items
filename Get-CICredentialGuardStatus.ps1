# use wmi to check if Credential Guard is running
# Stolen shamelessly from Microsoft's DG_Readyness_Tool_v3.2.ps1
# modified to return true or false.
# 0.1, 20180301, Robin Engström. 

function CheckDGRunning {
    # if one of the values in SecurtyServicesRunning is 2 = HVCI running. if 1 = CredGuard running
    $_val = 1
    $DGObj = Get-CimInstance -classname Win32_DeviceGuard -namespace root\Microsoft\Windows\DeviceGuard
    for ($i = 0; $i -lt $DGObj.SecurityServicesRunning.length; $i++) {
        
        if ($DGObj.SecurityServicesRunning[$i] -eq $_val) {
            return $true
        }

    }
    return $false
}

CheckDGRunning