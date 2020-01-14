function Set-adminUserAccount {
    <#
    .SYNOPSIS
    Set the password of local .\admin acccount
    .DESCRIPTION
    The Set-adminUserAccount function assigns the provided password to the local .\admin account.
    If account is not found, it is created.
    .PARAMETER Password
    Password to set.
    .EXAMPLE
    Set-adminUserAccount -password sEDkw7CEYhteGEx
    .NOTES
    Run using an elevated prompt to ensure smooth operation.
    The functions runs using Powershell, if availiable.
     If not, reverts back no legacy `net` commands.
    .NOTES
        Created:    2019-04-24
        Version:    1.0

        Disclaimer:
        This script is provided 'AS IS' with no warranties, confers no rights and 
        is not supported by the author.

        Version:    1.1
        Added /Y to automatically accept 'net user' error
        ""the password entered is longer than 14 characters..""
    #>

    [CmdletBinding(
        DefaultParameterSetName = 'Secret'
    )]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Security.SecureString]$Password
    )
    function Resolve-Command($cmdName) {
        return [bool](Get-Command -Name $cmdName -ErrorAction SilentlyContinue)
    } ## END Resolve-Command

    $admincreated = $false

    Write-Host "Set-adminUserAccount"
    Write-Host "=============================="
    Write-Host "Looking for local admin account..."
    Write-Host `r

    if (Resolve-Command -cmdName 'Get-LocalUser') {
        $localadmin = (Get-LocalUser -Name "admin" -ErrorAction SilentlyContinue)
        if ($localadmin) {
            Write-Host "Local admin account found."
            # Set local .\admin password
            Set-LocalUser $localadmin.Name -Password $Password
        } else {
            Write-Host "Local admin account not found... Creating"
            # Create local .\admin account
            $localadmin = New-LocalUser -Name "admin" -FullName "admin" -Description "Administrative Account." -Password $Password -PasswordNeverExpires
            Add-LocalGroupMember -Group (Get-LocalGroup -SID S-1-5-32-544).Name -Member $localadmin.Name
            Enable-LocalUser -Name $localadmin.Name
            $admincreated = $true
        }
    } else {
        if ([bool](net user "admin")) {
            Write-Host "Local admin account found."
            # Set local .\admin password
            Net User admin $Password
            # Set password never expires
            $user = [adsi]"WinNT://$env:computername/admin"
            $user.UserFlags.value = $user.UserFlags.value -bor 0x10000
            $user.CommitChanges()
        } else {
            Write-Host "Local admin account not found... Creating"
            # Add custom local admin account
            $localGroup = "administrators"
            net user "admin" $Password /add /Y
            net localgroup $localGroup "admin" /add
            # Set account description
            $user = [adsi]"WinNT://$env:computername/admin"
            $user.Description="Administrative Account."
            $user.SetInfo()
            # Set password never expires
            $user.UserFlags.value = $user.UserFlags.value -bor 0x10000
            $user.CommitChanges()
            $admincreated = $true
        }
    }

    if (Resolve-Command -cmdName 'Get-LocalUser') {
        if ((Get-LocalUser -Name "admin").PasswordLastSet -gt (Get-Date).AddMinutes(-5)) {
            if ($admincreated) {
                Write-Host -ForegroundColor Green "Local admin sucessfully created!"
            } else {
                Write-Host -ForegroundColor Green "Local admin sucessfully updated!"
            }
        }
    } else {
        if (![bool]($user)) {
            $user = [adsi]"WinNT://$env:computername/admin"
        }
        if ($user.PasswordAge -lt 300) {
            if ($admincreated) {
                Write-Host -ForegroundColor Green "Local admin sucessfully created!"
            } else {
                Write-Host -ForegroundColor Green "Local admin sucessfully updated!"
            }
        }
    }

} ## END Set-adminUserAccount

$passwordOk = $false

if (([string]$env:usrPassword).Length -gt 12) {
    $encryptedPassword = ConvertTo-SecureString $env:usrPassword -AsPlainText -Force
    $passwordOk = $true
} else {
    Write-Host -ForegroundColor Red "Password not long enough. Min length: 12"
}

if ($passwordOk) { Set-adminUserAccount -Password $encryptedPassword }
