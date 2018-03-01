# kolla gruppmedlemsskap
# parsa alla foldrar och se var samma konto har write
<#
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$acl = get-acl C:\temp # System.Security.AccessControl.DirectorySecurity
$folder = get-item -Path c:\temp
#$rules = $acl.GetAccessRules($true, $true, System.Security.Principal.SecurityIdentifier)
$rules = $folder.GetAccessControl().GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) # System.Security.AccessControl.FileSystemAccessRule
foreach ($access in $acl) 
{ 
    if ($access.Groups.Contains($user.IdentityReference)) 
    { 
        write-host $access.FileSystemRights
    }
}
#>
# nytt på fm

$aclfolder = get-acl C:\temp
$accessRight = [System.Security.AccessControl.FileSystemRights]::Write
$useridentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$aclacl = $aclfolder.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

foreach ($rule in $aclacl) {
    #write-host $rule.IdentityReference

    # Groups innehåller alla grupper, som SID, som användaren är med i!
    # så: om användaren, eller nån av dens grupper finns i rule.identityreference
    if ($useridentity.Groups.Contains($rule.IdentityReference)) {
        #..och om accesright jämfört med filesystemright är samma som accesright?!
        # okej, bitwise AND betyder att: 011 band 010 = 010. accessregeln måste lagras som en bitmask.
        if (($AccessRight -band $rule.FileSystemRights) -eq $AccessRight) {
            if ($rule.AccessControlType -eq "Allow") {
                write-host "hmmmmm"
            }
        }
    }
}

# access rights: https://msdn.microsoft.com/en-us/library/windows/desktop/aa374896(v=vs.85).aspx

<#
    public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
    {
        if (string.IsNullOrEmpty(DirectoryPath)) return false;

        try
        {
            AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference))
                {
                    if ((AccessRight & rule.FileSystemRights) == AccessRight)
                    {
                        if (rule.AccessControlType == AccessControlType.Allow)
                            return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }
#>