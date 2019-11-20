#Get Services

$services = Get-Service

foreach ($s in $services){
    [String] $Sddl = sc.exe sdshow $s.Name

    $Header = $Sddl -split '([A-Z]:)'[1]
    "The Headers for $s are:"
    Write-Host $Header
}