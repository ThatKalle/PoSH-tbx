<#
    .SYNOPSIS
    Create a catch-all subdomain and forward incomming mail to a Distribution Group in primary domain.
    .DESCRIPTION
    Set up a subdomain to act as catch-all in o365 and forward email to a distribution group.
    Should be used with care as there is no recipient filtering enabled this way, but it removes the need to create separate aliases to recieve emails.
    Workes by setting the subdomain as InteralRelay followed coupled with a Transport rule to forward all incomming email to a Shared mailbox who inturn forwards to a Distribution group.
     (Transport rules can't as of writing forward directly to a group)
    .INPUTS
    Needs o365 Administrative cretentials via $UserCredential
    .OUTPUTS
    Shared Mailbox: $sharedMbx
    Distribution Group: $distGrp
    Transport Rule: "$subDomain Catch-All Transport Rule"
    .EXAMPLE
    .\O365-CatchAllDomain.ps1
    .NOTES
    Assumes subdomain registration and validation already complete.
    # https://support.office.com/en-us/article/Domains-FAQ-1272bad0-4bd4-4796-8005-67d6fb3afc5a#bkmk_caniaddcustomsubdomainsormultipledomainstooffice365
    .NOTES
    Remember to swap the # Variables to match your settings.
#>

# Connect to Office 365
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session

# Variables
$subDomain = "news.contoso.com"
$sharedMbx = "news@$subDomain"
$distGrp = "newsteam@contoso.com"

# Set Subdomain to InternalRelay (Accept all incomming messages)
Get-AcceptedDomain $subDomain | Set-AcceptedDomain -DomainType InternalRelay

# Create Distribution Group $distGrp, enable external emails and hide from GAL
New-DistributionGroup -Name $distGrp -PrimarySmtpAddress $distGrp -RequireSenderAuthenticationEnabled $false -MemberJoinRestriction closed | Set-DistributionGroup -HiddenFromAddressListsEnabled $True

# Create Shared Mailbox $sharedMbx and set forward to $distGrp
New-Mailbox -Shared -Name $sharedMbx -DisplayName $sharedMbx -PrimarySmtpAddress $sharedMbx | Set-Mailbox -ForwardingAddress $distGrp

# Create CatchAll TransportRule
New-TransportRule -Name "$subDomain Catch-All Transport Rule" -SenderAddressLocation HeaderOrEnvelope -RecipientDomainIs $subDomain -RedirectMessageTo $sharedMbx -Comments "Forward all messages for *@$subDomain to $sharedMbx who forwards to $distGrp."
