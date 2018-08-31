# check if PowerShell Version 2 is installed (may be used for evasion of logging and Language Mode restrictions)

if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq "Disabled") {
    return $false
}
else {
    return $true
}
