#this creates the SID for the four users alerting.
#creates a NTAccount object
#translates it to an SID
$wanted_sids = @(
    "Everyone",
    "Authenticated Users",
    "Domain Users",
    "Users"
) | ForEach-Object -Process {
    $account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $_
    $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

$RightsToCheck = 0xc0002  # ChangeConfig, ChangePermissions, ChangeOwner

$services = Get-Service 

#loops through every service
#gets the SDDL
#creates a security descriptor object
#then loops through the SIDs
#checks if the SecurityDescriptor's DiscretionaryACL has an "Allow" ACE, the SID, and has the rights.
#if they exist, it removes them and prints the string version
foreach ($s in $services){
    $ServiceName = $s.Name
    [String] $Sddl = sc.exe sdshow $ServiceName

    #attempt to create a security descriptor object
    try {
        $SD = New-Object System.Security.AccessControl.CommonSecurityDescriptor(
            $false,  # Not a container
            $false,  # Not a DS Object
            $Sddl
        )
    }

    catch {
        Write-Warning ("Error creating security descriptor for {0}: {1}" -f $ServiceName, $_.Exception.Message)
    }

    #
    foreach ($sid in $wanted_sids){
        if ($SD.DiscretionaryAcl | where { $_.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and $_.SecurityIdentifier -eq $sid -and $_.AccessMask -band $RightsToCheck }) {
            $null = $SD.DiscretionaryAcl.RemoveAccess(
                "Allow",   # ACE type
                $sid,
                $RightsToCheck,
                "ContainerInherit, ObjectInherit", # InheritanceFlags
                "None"  #PropagationFlags
            )

            $updatedSddl = $SD.GetSddlForm("All")
            $sidAccount = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sid
            $objUser = $sidAccount.Translate( [System.Security.Principal.NTAccount]) #translate the SID back to the user for easy readability

            [PSCustomObject] @{
                Service = $ServiceName
                SID = $objUser
                OriginalSddl = $Sddl
                UpdatedSddl = $updatedSddl
            }

            "Changing the SDDL..."
            sc.exe sdset $ServiceName $updatedSddl #comment this out if you don't want it to change it automatically and just want to do it manually
        }
    }

}

