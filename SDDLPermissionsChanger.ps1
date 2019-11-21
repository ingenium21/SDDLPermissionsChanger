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

foreach ($s in $services){
    $ServiceName = $s.Name
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

            [PSCustomObject] @{
                Service = $ServiceName
                SID = $sid
                OriginalSddl = $Sddl
                UpdatedSddl = $updatedSddl
            }

            #uncomment the line below to have the script change the Sddl for you.
            #sc.exe sdsset $ServiceName $updatedSddl
        }
    }

}

