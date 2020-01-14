<#
    .SYNOPSIS
    Disables and moves inactive computer objects to standardized OU.
    .DESCRIPTION
    Looks for and creates a standardized "InactiveComputers" OU in the AD structure.
    'OU=InactiveComputers,DC=Contoso,DC=com'
    Disables and notes old Computer objects.
    Moves old Computer objects to above OU.
    .NOTES
    Needs access to the 'ActiveDirecoty' PS Module, run on a DC using an elevated prompt to ensure smooth runnings.
    .NOTES
        Created:    2018-12-28
        Version:    1.0

        Disclaimer:
        This script is provided 'AS IS' with no warranties, confers no rights and 
        is not supported by the author.
#>

function New-OU ([string]$name, [string]$path, [string]$description) {
    # Modules
    if (!(Get-Module ActiveDirectory)) {
        Import-Module ActiveDirectory
    }

    # Variables
    $ouDN = "OU=$name,$path"

    # Check if the OU exists
    try {
        Get-ADOrganizationalUnit -Identity $ouDN | Out-Null
        Write-Host "OU '$ouDN' already exists."
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Host "Creating new OU '$ouDN'"
        New-ADOrganizationalUnit -Name $name -Path $path -Description $description
    }
} ## END New-OU

function Disable-ADComputers ($daysInactive, $caseNumber) {
    <#
        .SYNOPSIS
        Cleanup old computer objects in AD
        .DESCRIPTION
        The Disable-ADComputers function queries the AD of Computer Objects not having reset their password prior to $daysInactive
        (Computers not contacted the AD)
        The function moved the objects, disabled them, and sets a description.
        .PARAMETER daysInactive
        Amount of graceperiod days.
        Default: 90
        .PARAMETER caseNumber
        (optional)
        Case number added to end of description on disabled objects.
        .OUTPUTS
        The Disable-ADComputers function will output a .txt file in the C:\Temp\ folder listing all processed objects.
        A manual restore should be doable with this information.
        C:\Temp\InactiveComputers_BeforeMove_yyMMdd-NUM.txt
        .EXAMPLE
        Disable-ADComputers -daysInactive 90 -caseNumber "Ticket1234"
        .NOTES
        Needs access to the 'ActiveDirecoty' PS Module, run on a DC using an elevated prompt to ensure smooth runnings.
        .NOTES
            Created:    2018-12-28
            Version:    1.0

            Disclaimer:
            This script is provided 'AS IS' with no warranties, confers no rights and 
            is not supported by the author.
    #>
    if ($null -eq $daysInactive) {
        $daysInactive = 90
    }
    # Modules
    if (!(Get-Module ActiveDirectory)) {
        Import-Module ActiveDirectory
    }
   
    # Variables
    $now = Get-Date -Format yyMMdd
    $random = Get-Random
    $date = (Get-Date).AddDays(-($DaysInactive))
    $domainDC = (Get-ADDomain).DistinguishedName
    $inactiveOUName = "InactiveComputers"
    $inactiveOU = "OU=$inactiveOUName,$domainDC"

    # Create Inactive Computers OU if it doesn't exist
    # Find all Computers with $PasswordLastSet prior to X days
    New-OU -name $inactiveOUName -path $domainDC -description "Inactive Computer Objects"
    $inactiveComputers = Get-ADComputer -Filter 'PasswordLastSet -le $date' -SearchBase "$domainDC" -properties * | Where-Object { $_.DistinguishedName -NotLike "*$inactiveOU" }

    # Quick .txt Backup
    New-Item -Path C:\Temp -ItemType Directory -Force | Out-Null
    $inactiveComputers | Format-Table DistinguishedName, PasswordLastSet, Name, Description | Out-File C:\Temp\InactiveComputers_BeforeMove_$now-$random.txt
    if (Test-Path C:\Temp\InactiveComputers_BeforeMove_$now.txt) { Write-Host "Backup List created: C:\Temp\InactiveComputers_BeforeMove_$now-$random.txt" -ForeGroundColor Green }
    
    # Move, Disable, Set Description
    Write-Host "Disabling computer objects with inactivity greater than $daysInactive days, $date" -ForeGroundColor Yellow
    foreach ($inactiveComputer in $inactiveComputers) {
        if ($null -eq $inactiveComputer.Description) {
            $inactiveComputer | Set-ADComputer -Description "Disabled $now due to inactivity - $caseNumber"
        } else {
            $inactiveComputer | Set-ADComputer -Description "$($inactiveComputer.Description) | Disabled $now due to inactivity - $caseNumber"
        }
        $inactiveComputer | Disable-ADAccount
        $inactiveComputer | Move-ADObject -TargetPath "$inactiveOU"
        Write-Host "Computer Processed: $($inactiveComputer.Name)"
    }
} ## END Disable-ADComputers
