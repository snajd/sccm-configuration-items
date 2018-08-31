
#function Get-WritableFolders {
    [CmdletBinding()]
    param (
        $path
    )
    
    begin {
        $fsr = [System.Security.AccessControl.FileSystemRights]
        $writeaccessright = $fsr::Write
        $denyaccesstype = [System.Security.AccessControl.AccessControlType]::Deny
        $useridentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    }
    
    process {

        Get-ChildItem -Recurse $path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $acl = get-acl $_.FullName -ErrorAction SilentlyContinue
            }
            catch [System.UnauthorizedAccessException] {
                Write-Verbose "Permission denied"
            }

            foreach ($rule in $acl.Access) {
                try {
                    # om ACE endast innehåller "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" så funkar inte Translate
                    if (($rule.IdentityReference -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -or 
                        ($rule.IdentityReference -eq "APPLICATION PACKAGE AUTHORITY\Software and hardware certificates or a smart card")) {
                        
                            Write-Verbose "$PSitem includes ACE with stuff we cant translate"
                        break
                    }

                    # är jag , eller någon grupp jag är medlem i med i någon ACE?
                    if (($useridentity.Groups.Contains($rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]))) -or ($useridentity.User.Value -eq $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]))) {
                    # har jag deny på write?
                        if ($rule.AccessControlType -eq $denyaccesstype) {
                            break
                        }                    
                        elseif ($rule.FileSystemRights.HasFlag($writeaccessright)) {
                            #Write-Output "$($_.Fullname) is Writable by $($useridentity.Name)"
                            #$obj = ""
                            #$obj = [PSCustomObject]@{
                            #    Folder = $($_.Fullname)
                            #    Writable = $true}
                            return $($_.FullName)                          
                        }
                    }
                }
                catch [System.Security.Principal.IdentityNotMappedException] {
                    Write-Verbose "Coulnd not translate ACE for $($_.FullName)"
                }
                catch [Exception] {
                    Write-Verbose "något annat blev fel"
                }
            }
            
        }
    }
    
    end {
    }
#}
