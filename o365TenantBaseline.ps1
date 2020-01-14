### https://docs.microsoft.com/en-us/office365/enterprise/powershell/connect-to-office-365-powershell
### https://docs.microsoft.com/sv-se/skypeforbusiness/set-up-your-computer-for-windows-powershell/set-up-your-computer-for-windows-powershell
###  https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads

#$FormatEnumerationLimit=-1


## Functions ##
Function Connect-EXOnline {
    $credentials = Get-Credential
    Write-Host "Getting the Exchange Online cmdlets" -ForegroundColor Yellow
    $session = New-PSSession -ConfigurationName Microsoft.Exchange `
        -ConnectionUri https://outlook.office365.com/powershell-liveid/ `
        -Credential $credentials -Authentication Basic -AllowRedirection
    Import-PSSession $session -AllowClobber
} ## END Connect-EXOnline 
## Connect-EXOPSSession

Function Connect-SecurityComplianceCenter {
    $credentials = Get-Credential
    Write-Host "Getting the Security & Compliance Center cmdlets" -ForegroundColor Yellow
    $session = New-PSSession -ConfigurationName Microsoft.Exchange `
        -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ `
        -Credential $credentials -Authentication Basic -AllowRedirection
    Import-PSSession $session -AllowClobber
} ## END Connect-SecurityComplianceCenter

Function Connect-SFBOnline {
    $adminUPN = Read-Host -Prompt 'Please enter the user principal name (ex. admin@domain.onmicrosoft.com)'
    Write-Host "Getting the Skype for Business Online cmdlets" -ForegroundColor Yellow
    $sfboSession = New-CsOnlineSession -UserName $adminUPN
    Import-PSSession $sfboSession -AllowClobber
} ## END Connect-SFBOnline

Function Enable-UnifiedAuditLog {
    $unifiedAditLogStatus = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
    if (!$unifiedAditLogStatus -eq $true) {
        Write-Host "Unified audit log - Enabled" -ForegroundColor Green
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction SilentlyContinue  
    }
} ## END Enable-UnifiedAuditLog

Function Enable-AdmindAuditLog {
    $adminAditLogStatus = (Get-AdminAuditLogConfig).AdminAuditLogEnabled
    if (!$adminAditLogStatus -eq $true) {
        Write-Host "Admin audit log - Enabled" -ForegroundColor Green
        Set-AdminAuditLogConfig -AdminAuditLogEnabled $true -AdminAuditLogCmdlets * -AdminAuditLogParameters * -ErrorAction SilentlyContinue  
    } elseif (!$adminAditLogStatus -eq $true) {
        Write-Host "Admin audit log - Enabled" -ForegroundColor Green
    }
} ## END Enable-AdmindAuditLog

Function Enable-MailboxAuditlogging {
    if(!(Get-OrganizationConfig).AuditDisabled -eq $false) {
        Write-Host "Mailbox Auditlogging feature - Enabled" -ForegroundColor Green
        Set-OrganizationConfig -AuditDisabled $false
    }
    Write-Host "Mailbox Auditlogging" -ForegroundColor Yellow
    foreach($mbx in (Get-Mailbox -ResultSize Unlimited)) {
        if(!$mbx.AuditEnabled -eq $true) {
            Write-Host ("Mailbox Auditlogging - enabled on mailbox: " + $mbx.WindowsEmailAddress ) -ForegroundColor Green
            Set-Mailbox $mbx.WindowsEmailAddress -AuditEnabled $true -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
    }
} ## END Enable-MailboxAuditlogging

Function Disable-POPImap {
    Write-Host "IMAP/POP support - Disabled" -ForegroundColor Green
    Get-CASMailboxPlan -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } | Set-CASMailboxPlan -ImapEnabled $false -PopEnabled $false
    Write-Host "Mailbox IMAP/POP support - Disabled" -ForegroundColor Green
    Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } | Select-Object @{Name= "Identity"; Expression = {$_.PrimarySmtpAddress}} | Set-CASMailbox -ImapEnabled $false -PopEnabled $false -WarningAction SilentlyContinue
} ## END Disable-POPImap

function Set-EndUserSpamNotification 
{
    #[CmdletBinding()]
    #param (
    #    $EndUserSpamNotificationFrequency
    #)
    Set-HostedContentFilterPolicy -Identity Default `
        -EndUserSpamNotificationFrequency 1 `
        -EndUserSpamNotificationLanguage Default `
        -HighConfidenceSpamAction Quarantine `
        -EnableEndUserSpamNotifications $true
} ## END Set-EndUserSpamNotification 

function Set-OutboundSpamFilterNotification 
{
    [CmdletBinding()]
    param (
        $Emailaddress
    )
    Set-HostedOutboundSpamFilterPolicy Default -NotifyOutboundSpamRecipients $Emailaddress -NotifyOutboundSpam $true
} ## END Set-OutboundSpamFilterNotification 

function Push-Contacts 
{
    [CmdletBinding()]
    param (
        $Name,
        $Emailaddress
    )
    $contact = Get-Contact | Where-Object {$_.EmailAddress -eq $Emailaddress}
    if (!$contact) {
        Write-Host ("Contact not found, creating contact " + $Emailaddress) -ForegroundColor Green
        New-MailContact -Name $Name -ExternalEmailAddress $Emailaddress -Confirm:$false
    }
    elseif ($contact.Name -ne $Name) {
        Write-Host ("Contact found, updating contact " + $Emailaddress) -ForegroundColor Green
        $contact | Set-Contact -Name $Name -DisplayName $Name -Confirm:$false
    } else {
        Write-Host ("Contact found " + $Emailaddress) -ForegroundColor Green
    }
    Set-HostedContentFilterPolicy -Identity Default -AllowedSenders @{Add=$Emailaddress}
} ## END Push-Contacts

function Set-MDMbPolicy {
#https://docs.microsoft.com/en-us/powershell/module/exchange/devices/set-mobiledevicemailboxpolicy?view=exchange-ps
    $gg = Get-MobileDeviceMailboxPolicy -Identity Default
    if (
        ($gg.PasswordEnabled -eq $True) -and `
        (($gg.AllowSimplePassword -eq $True) -or ($gg.AlphanumericPasswordRequired -eq $True)) -and `
        ($gg.MinPasswordLength -ge 4) -and `
        ($gg.RequireDeviceEncryption -eq $True) -and `
        ($gg.AllowNonProvisionableDevices -eq $False)
       ) {
           Write-Host ("MobileDeviceMailboxPolicy conforms to/or greater than baseline") -ForegroundColor Green
       } else {
        Write-Host ("Deploying baseline MobileDeviceMailboxPolicy") -ForegroundColor Green
        Set-MobileDeviceMailboxPolicy -Identity Default `
            -PasswordEnabled $true `
            -AllowSimplePassword $true `
            -MinPasswordLength 4 `
            -RequireDeviceEncryption $true `
            -AllowNonProvisionableDevices $false
       }
} ## END Set-MDMbPolicy

function Enable-ModernAuth {
    if (!((Get-OrganizationConfig).OAuth2ClientProfileEnabled -eq $True)) {
        Write-Host "ModernAuth enabled - Office Apps" -ForegroundColor Green
        Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
    }
    if (!((Get-CsOAuthConfiguration).ClientAdalAuthOverride -eq "Allowed")) {
        Write-Host "ModernAuth enabled - SFBo" -ForegroundColor Green
        Set-CsOAuthConfiguration -ClientAdalAuthOverride Allowed
    }
} ## END Enable-ModernAuth

function Set-O365PasswordNeverExpires {
    $domains = Get-MsolDomain | Where-Object {($_.Status -eq "Verified") -and ($_.RootDomain -eq $null)}
    foreach($domain in $domains) {
        $domainStatus = Get-MsolPasswordPolicy -DomainName $domain.Name
        if($domainStatus.ValidityPeriod -ne 2147483647) {
            Write-Host "Setting the Password Expiration Policy on $($domain.Name)"
            Set-MsolPasswordPolicy -DomainName $domain.Name -ValidityPeriod 2147483647 -NotificationDays 30
        }
    }
} ## END Set-O365PasswordNeverExpires

function Push-TransportRules {
    ## Block Inbox Rules from forwarding mail externally
    $externalTransportRuleName = "Inbox Rules To External Block"
    $rejectMessageText = "To improve security, auto-forwarding rules to external addresses has been disabled. Please contact your Microsoft Partner if you'd like to set up an exception."
    
    $externalForwardRule = Get-TransportRule | Where-Object {$_.Name -eq $externalTransportRuleName}
    
    if (!$externalForwardRule) {
        Write-Output "Client Rules To External Block not found, creating Rule"
        New-TransportRule -Name $externalTransportRuleName -Priority 0 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText -Mode Audit
    }

    ## Warn users if inbound external mail with displayname matching internal users.
    $ruleName = "External Senders with matching Display Names"
    $ruleHtml = "<table class=MsoNormalTable border=0 cellspacing=0 cellpadding=0 align=left width=`"100%`" style='width:100.0%;mso-cellspacing:0cm;mso-yfti-tbllook:1184; mso-table-lspace:2.25pt;mso-table-rspace:2.25pt;mso-table-anchor-vertical:paragraph;mso-table-anchor-horizontal:column;mso-table-left:left;mso-padding-alt:0cm 0cm 0cm 0cm'>  <tr style='mso-yfti-irow:0;mso-yfti-firstrow:yes;mso-yfti-lastrow:yes'><td style='background:#910A19;padding:5.25pt 1.5pt 5.25pt 1.5pt'></td><td width=`"100%`" style='width:100.0%;background:#FDF2F4;padding:5.25pt 3.75pt 5.25pt 11.25pt; word-wrap:break-word' cellpadding=`"7px 5px 7px 15px`" color=`"#212121`"><div><p class=MsoNormal style='mso-element:frame;mso-element-frame-hspace:2.25pt; mso-element-wrap:around;mso-element-anchor-vertical:paragraph;mso-element-anchor-horizontal: column;mso-height-rule:exactly'><span style='font-size:9.0pt;font-family: `"Segoe UI`",sans-serif;mso-fareast-font-family:`"Times New Roman`";color:#212121'>This message was sent from outside the company by someone with a display name matching a user in your organization. Please do not click links or open attachments unless you recognize the source of this email and know the content is safe. <o:p></o:p></span></p></div></td></tr></table><br><br>"

    $rule = Get-TransportRule | Where-Object {$_.Identity -contains $ruleName}
    $displayNames = (Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox).DisplayName
    
    if (!$rule) {
        Write-Host "Rule not found, creating rule" -ForegroundColor Green
        New-TransportRule -Name $ruleName -Priority 0 -FromScope "NotInOrganization" -ApplyHtmlDisclaimerLocation "Prepend" `
            -HeaderMatchesMessageHeader From -HeaderMatchesPatterns $displayNames -ApplyHtmlDisclaimerText $ruleHtml
    }
    else {
        Write-Host "Rule found, updating rule" -ForegroundColor Green
        Set-TransportRule -Identity $ruleName -Priority 0 -FromScope "NotInOrganization" -ApplyHtmlDisclaimerLocation "Prepend" `
            -HeaderMatchesMessageHeader From -HeaderMatchesPatterns $displayNames -ApplyHtmlDisclaimerText $ruleHtml
    }

    ## Report Message addin submissions
    $externalTransportRuleName = "Report Message submissions"
    
    $externalForwardRule = Get-TransportRule | Where-Object {$_.Name -eq $externalTransportRuleName}
    
    if (!$externalForwardRule) {
        Write-Output "Report Message submissions not found, creating Rule"
        New-TransportRule -Name $externalTransportRuleName -Priority 2 -RecipientAddressContainsWords "phish@office365.microsoft.com, junk@office365.microsoft.com" -BlindCopyTo "cust.o365.alerts@contoso.com" -Mode Audit -SetAuditSeverity Medium
    }

} ## END Push-TransportRules

function push-ActivityAlert {
    [CmdletBinding()]
    param (
        $Emailaddress
    )
    $ruleName = "Elevation of Privilege Alert"
    $alert = $null
    $alert = Get-ActivityAlert -Identity $ruleName -ErrorAction SilentlyContinue
    if (!$alert) {
        $newAlert = New-ActivityAlert -Name $ruleName -NotifyUser $Emailaddress -Type ElevationOfPrivilege -Severity High -Category AccessGovernance
        if ($newAlert) {
            Write-Host "Alert created" -ForegroundColor Green
        }
    }
    else {
        Write-Host "Alert already exists" -ForegroundColor Green
    }
} ## END push-ActivityAlert








Function Test-TenantBaseline {
    Write-Host "Performing TenantBaseline Check..." -ForegroundColor Yellow
    $checks = @(
        #'UnifiedAuditLog', `
        'AdminAuditLog', `
        'MailboxAuditlogging' , `
        'POPIMAP', `
        'TNEFEnabled', `
        'EndUserSpamNotification', `
        'OutboundSpamFilterNotification', `
        'Contacts', `
        'MDMbPolicy', `
        'ModernAuthEnabled', `
        'TechnicalNotification', `
        'PasswordNeverExpiresDomain', `
        'TransportRules', `
        #'ActivityAlert', `
        'FocusedInbox'
        )
    
    switch ($checks) {
        'UnifiedAuditLog' {
            switch ((Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) {
                $true {Write-Host "Unified audit log - Enabled" -ForegroundColor Green}
                $false {Write-Host "Unified audit log - Not enabled" -ForegroundColor Red}
                default {Write-Host "Unified audit log - Take a look" -ForegroundColor Yellow}
            }
        }
        'AdminAuditLog' {
            switch ((Get-AdminAuditLogConfig).AdminAuditLogEnabled) {
                $true {Write-Host "Admin audit log - Enabled" -ForegroundColor Green}
                $false {Write-Host "Admin audit log - Not enabled" -ForegroundColor Red}
                default {Write-Host "Admin audit log - Take a look" -ForegroundColor Yellow}
            }
        }
        'MailboxAuditlogging' {
            switch ((Get-OrganizationConfig).AuditDisabled) {
                $true {Write-Host "Mailbox Auditlogging feature - Not enabled" -ForegroundColor Red}
                $false {Write-Host "Mailbox Auditlogging feature - Enabled" -ForegroundColor Green}
                default {Write-Host "Mailbox Auditlogging feature - Take a look" -ForegroundColor Yellow}
            }

            if ($aa = Get-Mailbox -ResultSize Unlimited | where-object {($_.AuditEnabled -eq $false)}) {
                foreach ($a in $aa) {
                    Write-Host ("Mailbox Auditlogging - Not enabled on mailbox: " + $a.WindowsEmailAddress ) -ForegroundColor Red
                }
            } else {
                Write-Host "Mailbox Auditlogging - Enabled on all mailboxes" -ForegroundColor Green
            }
        }
        'POPIMAP' {
            if ($bb = Get-CASMailboxPlan -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" }) {
                foreach ($b in $bb) {
                    Write-Host ("IMAP/POP support - Enabled on CASMailboxPlan: " + $b.DisplayName ) -ForegroundColor Red
                }
            } else {
                Write-Host "IMAP/POP support - Disabled on all CASMailboxPlans" -ForegroundColor Green
            }

            if ($cc = Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" }) {
                foreach ($c in $cc) {
                    Write-Host ("Mailbox IMAP/POP support - Enabled on mailbox: " + $c.PrimarySmtpAddress ) -ForegroundColor Red
                }
            } else {
                Write-Host "Mailbox IMAP/POP support - Disabled on all mailboxes" -ForegroundColor Green
            }
        }
        'TNEFEnabled' {
            switch ((Get-RemoteDomain Default).TNEFEnabled) {
                $true {Write-Host "WINMAIL.dat potential error" -ForegroundColor Red}
                $false {Write-Host "WINMAIL.dat potential error - Alleviated" -ForegroundColor Green}
                default {Write-Host "WINMAIL.dat - Take a look" -ForegroundColor Yellow}
            }
        }
        'EndUserSpamNotification' {
            $dd = Get-HostedContentFilterPolicy Default
            switch ($dd.EnableEndUserSpamNotifications) {
                $true {Write-Host ("EndUserSpamNotification - Enabled, Frequency: " + $dd.EndUserSpamNotificationFrequency) -ForegroundColor Green}
                $false {Write-Host "EndUserSpamNotification - Not enabled" -ForegroundColor Red}
                default {Write-Host "EndUserSpamNotification - Take a look" -ForegroundColor Yellow}
            }
        }
        'OutboundSpamFilterNotification' {
            $ee = Get-HostedOutboundSpamFilterPolicy
            switch ($ee.NotifyOutboundSpam) {
                $true {Write-Host ("NotifyOutboundSpam - Enabled, Recipients: " + $ee.NotifyOutboundSpamRecipients) -ForegroundColor Green}
                $false {Write-Host "NotifyOutboundSpam - Not enabled" -ForegroundColor Red}
                default {Write-Host "NotifyOutboundSpam - Take a look" -ForegroundColor Yellow}
            }
        }
        'Contacts' {
            if ($ff = Get-Contact | Where-Object {$_.WindowsEmailAddress -like "*contoso.com*"}) {
                foreach ($f in $ff) {
                    Write-Host ("Contact found: " + $f.DisplayName + " (" + $f.WindowsEmailAddress +")" ) -ForegroundColor Green
                } 
            } else {
                Write-Host "No contact found" -ForegroundColor Red
            }
        }
        'MDMbPolicy' {
            $gg = Get-MobileDeviceMailboxPolicy -Identity Default
            if (
                ($gg.PasswordEnabled -eq $True) -and `
                (($gg.AllowSimplePassword -eq $True) -or ($gg.AlphanumericPasswordRequired -eq $True)) -and `
                ($gg.MinPasswordLength -ge 4) -and `
                ($gg.RequireDeviceEncryption -eq $True) -and `
                ($gg.AllowNonProvisionableDevices -eq $False)
            ) {
                Write-Host ("MobileDeviceMailboxPolicy conforms to/or greater than baseline") -ForegroundColor Green
            } elseif (
                ($gg.AllowNonProvisionableDevices -eq $True) -or `
                ($gg.RequireDeviceEncryption -eq $False) -or `
                ($gg.MinPasswordLength -le 4) -or `
                ($gg.PasswordEnabled -eq $False)
            ) {
                Write-Host ("MobileDeviceMailboxPolicy not compliant") -ForegroundColor Red
            } else {
                Write-Host ("MobileDeviceMailboxPolicy not inline with baseline") -ForegroundColor Yellow
            }
        }
        'ModernAuthEnabled' {
            switch ((Get-OrganizationConfig).OAuth2ClientProfileEnabled) {
                $true {Write-Host "ModernAuth (Office Apps) - Enabled" -ForegroundColor Green}
                $false  {Write-Host "ModernAuth (Office Apps) - Disabled" -ForegroundColor Red}
                default {Write-Host "ModernAuth (Office Apps) - Take a look" -ForegroundColor Yellow}
            }
            switch ((Get-CsOAuthConfiguration).ClientAdalAuthOverride) {
                'Allowed' {Write-Host "ModernAuth (Skype for Business Online) - Allowed" -ForegroundColor Green}
                'NoOverride' {Write-Host "ModernAuth (Skype for Business Online) - NoOverride" -ForegroundColor Yellow}
                $null {Write-Host "ModernAuth (Skype for Business Online) - Disabled" -ForegroundColor Res}
                default {Write-Host "ModernAuth (Skype for Business Online) - Take a look" -ForegroundColor Yellow}
            }   
        }
        'TechnicalNotification' {
            if ((Get-MsolCompanyInformation).TechnicalNotificationEmails -like "*contoso.com*") {
                Write-Host ("Company Technical Contact: " + (Get-MsolCompanyInformation).TechnicalNotificationEmails) -ForegroundColor Green
            } else {
                Write-Host ("Company Technical Contact: " + (Get-MsolCompanyInformation).TechnicalNotificationEmails) -ForegroundColor Red
            }
        }
        'PasswordNeverExpiresDomain' {
            $domains = Get-MsolDomain | Where-Object {($_.Status -eq "Verified") -and ($_.RootDomain -eq $null)}
            foreach($domain in $domains) {
                $domainStatus = Get-MsolPasswordPolicy -DomainName $domain.Name
                if($domainStatus.ValidityPeriod -ne 2147483647) {
                    Write-Host "Password Expiration Policy not disabled on $($domain.Name)" -ForegroundColor Red
                } else {
                    Write-Host "Password Expiration Policy set to Never on $($domain.Name)" -ForegroundColor Green
                }
            }
        }
        'TransportRules' {
            $hhh = @("Inbox Rules To External Block", "External Senders with matching Display Names", "Report Message submissions")
            foreach ($hh in $hhh) {
                $h = Get-TransportRule | Where-Object {$_.Name -eq $hh}
                if (!$h) {
                    Write-Host ("Transport rule not funnd: " + $hh) -ForegroundColor Red
                } else {
                    switch ($h.Mode) {
                        'Enforce' {Write-Host ("Transport rule found: " + $h.Name + ", Mode: " + $h.Mode) -ForegroundColor Green}
                        'Audit' {Write-Host ("Transport rule found: " + $h.Name + ", Mode: " + $h.Mode) -ForegroundColor Yellow}
                        'AuditAndNotify' {Write-Host ("Transport rule found: " + $h.Name + ", Mode: " + $h.Mode) -ForegroundColor Yellow}
                        default {Write-Host ("Transport rule found: " + $h.Name + " - Take a look") -ForegroundColor Yellow}
                    }
                }
            }
        }
        'ActivityAlert' {
            $ruleName = "Elevation of Privilege Alert"
            $alert = Get-ActivityAlert -Identity $ruleName -ErrorAction SilentlyContinue
            if (!$alert) {
                Write-Host ("Alert " + $ruleName + " - Not found") -ForegroundColor Red
            } else {
                Write-Host ("Alert " + $ruleName + " - found, Recipient: " + $alert.NotifyUser) -ForegroundColor Green
            }
        }
        'FocusedInbox' {
            switch ((Get-OrganizationConfig).FocusedInboxOn) {
                $true {Write-Host "Focused Inbox - Enabled" -ForegroundColor Yellow}
                $false  {Write-Host "Focused Inbox - Disabled" -ForegroundColor Green}
                default {Write-Host "Focused Inbox - Take a look" -ForegroundColor Yellow}
            }
        }

    }
} ## END Test-TenantBaseline

## END Functions



## Connect everywhere to load modules, log in as admin. (without MFA)
#Connect-EXOnline
Connect-EXOPSSession
#Connect-SecurityComplianceCenter
#Connect-IPPSSession
Connect-MsolService
Connect-SFBOnline

#Variables
$CustomerDefaultDomain = (Get-MsolDomain | Where-Object {$_.IsInitial -eq $True}).Name
$CustomerPrimaryDomain = "contoso.com"
$CustomerNameAbr = "contoso"

## Enable OrganizationCustomization
Enable-OrganizationCustomization -ErrorAction SilentlyContinue

## AuditLogging
Enable-UnifiedAuditLog
Enable-AdmindAuditLog
Enable-MailboxAuditlogging

## System
Set-OrganizationConfig -FocusedInboxOn $false
Enable-ModernAuth
Set-O365PasswordNeverExpires
Set-MsolCompanyContactInformation -TechnicalNotificationEmails "$($CustomerNameAbr).o365@contoso.com"
#Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled:$false
# Disable POP/IMAP for all mailboxes
Disable-POPImap
# Fix WINMAIL.DAT potential error
Set-RemoteDomain Default -TNEFEnabled $false
# Spamsettings
Set-EndUserSpamNotification
Set-OutboundSpamFilterNotification -Emailaddress "cust.o365.alerts@contoso.com"
# Contacts
Push-Contacts -Name "Contoso Support" -Emailaddress "support@contoso.com"
Push-Contacts -Name "Contoso Sales" -Emailaddress "sales@contoso.com"
# MDMPolicy
Set-MDMbPolicy
Push-TransportRules
#push-ActivityAlert -Emailaddress "cust.o365.alerts@contoso.com"
# Enable Report Message add-in
#Set-App -Identity 6046742c-3aee-485e-a4ac-92ab7199db2e -OrganizationApp -PrivateCatalog -Enabled $True -DefaultStateForUser Enabled -ProvidedTo Everyone
# Rooms
Get-Mailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited | Set-CalendarProcessing -DeleteComments $False -DeleteSubject $False
foreach ($room in (Get-Mailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited)) {
    $roomalias = $room.alias
    Set-MailboxFolderPermission -Identity $roomalias":\Calendar" -User Default -AccessRights LimitedDetails
    Set-MailboxFolderPermission -Identity $roomalias":\Kalender" -User Default -AccessRights LimitedDetails
}

# SPF
# DKIM
Get-DkimSigningConfig
 #(Resolve-DnsName selector1._domainkey.$($CustomerPrimaryDomain) -Type CNAME).NameHost[0]
  ##selector1-<domainGUID>._domainkey.<initialDomain> 
 #(Resolve-DnsName selector2._domainkey.$($CustomerPrimaryDomain) -Type CNAME).NameHost[0]
  ##selector2-<domainGUID>._domainkey.<initialDomain> 
# Create "DMARC Reports" shared mailbox.
New-Mailbox -Shared -Name "DMARC Reports" -DisplayName "DMARC Reports" -PrimarySmtpAddress "_DMARC@$($CustomerPrimaryDomain)"
foreach ($domain in (Get-MsolDomain).name) { Get-Mailbox -Identity "DMARC Reports" | Set-Mailbox -EmailAddresses @{add="rua@$($domain)","ruf@$($domain)"} }
#Add-MailboxPermission -Identity "DMARC Reports" -User admin@$($CustomerDefaultDomain) -AccessRights FullAccess -InheritanceType All
# DMARC
 ##(Resolve-DnsName _dmarc.$($CustomerPrimaryDomain) -Type TXT).Strings
