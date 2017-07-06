<#
    .SYNOPSIS
    Performs external MX queries for all found configured AcceptedDomains in Exchange environment.

    .DESCRIPTION
    The script retrieves All configured AcceptedDomains in Exchange environment and checks the corresponding domain names for MX pointers via Googles public 8.8.8.8 NS server.
    This is a quick at-a-glance way to tell if a domain is no loinger in use in the envronment.
    Especially useful in Hosted solutions.

    .INPUTS
    None

    .OUTPUTS
    Two results generated;
    .\AcceptedDomainMXlookup_HARD.txt.
    Correct if MX = "MX preference = 10, mail exchanger = mx.domain.com".
    eg, only "correctly" configured domains.
    .\AcceptedDomainMXlookup_SOFT.txt.
    Correct if MX inc "mx.domain.com".
    eg, working, but not "correct".

    .EXAMPLE
    .\Get-AcceptedDomainMX.ps1

    .NOTES
    You need to run this script with Exchange modules enalbes as to be able to use 'Get-AcceptedDomain'.
    No changes are made to the Exhcnage envirorment.

    .NOTES
    Remember to swap the #Variables to match your settings.
#>

# Set Error Action to Silently Continue
    $ErrorActionPreference = "SilentlyContinue"

# Variables
    $mxHard = "MX preference = 10, mail exchanger = mx.domain.com"
    $mxSoft = "*mx.domain.com*"
    $dnsServer = "8.8.8.8"
    $domains = Get-AcceptedDomain
    $targetDir = ".\"

# Check for MX - HARD
    $output = foreach ($domain in $domains) {
        $nslookup = C:\Windows\system32\nslookup.exe -q=mx $domain.DomainName $dnsServer 2>$NULL
        if ($nslookup -match $mxHard) {
            Write-Host Correct: $domain.DomainName
            Write-Output "Correct: $($domain.DomainName)"
            Write-Output ""
        } else {
            Write-Host INCORRECT: $domain.DomainName
            Write-Output "INCORRECT: $($domain.DomainName)"
            Write-Output "Output from nslookup:"
            Write-Output "$nslookup"
            Write-Output ""
        }
    }
    $output | Out-File -filepath "$targetDir\AcceptedDomainMXlookup_HARD.txt"

# Check for MX - Soft
    $output = foreach ($domain in $domains) {
        $nslookup = C:\Windows\system32\nslookup.exe -q=mx $domain.DomainName $dnsServer 2>$NULL
        if ($nslookup -like $mxSoft) {
            Write-Host Correct: $domain.DomainName
            Write-Output "Correct: $($domain.DomainName)"
            Write-Output ""
        } else {
            Write-Host INCORRECT: $domain.DomainName
            Write-Output "INCORRECT: $($domain.DomainName)"
            Write-Output "Output from nslookup:"
            Write-Output "$nslookup"
            Write-Output ""
        }
    }
    $output | Out-File -filepath "$targetDir\AcceptedDomainMXlookup_SOFT.txt"
