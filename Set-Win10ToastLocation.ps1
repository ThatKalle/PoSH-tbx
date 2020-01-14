function Set-Win10ToastLocation {
    <#
    .SYNOPSIS
        Function to set Windows 10 Notification Toast location
    .DESCRIPTION
        
    .PARAMETER Position
        Expected Values: "Top" or "Bottom"
    .EXAMPLE
        Set-Win10ToastLocation -Position Top
    .OUTPUTS
        None
    .NOTES
        Version:        1.0
        Author:         Kalle Lilja
        Creation Date:  2019-07-27
        Purpose/Change: Initial script development
    #>
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Top", "Bottom")]
        [String[]]$Position
    )
    
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    $regName = "DisplayToastAtBottom"
    if ($Position -eq "Top") {$regValue = "0"} elseif ($Position -eq "Bottom") {$regValue = "1"} else {Write-Host "Position value error"}


    if (!(Get-ItemProperty -Path $regPath -Name $regName -ea 0)) {
        # IF Regkey does not Exist:
        # Create it, set value provided
        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null
        if ((Get-ItemProperty -Path $regPath -Name $regName -ea 0).$($regName) -eq $regValue) {
            # Validate, Output
            Write-Host -ForegroundColor Green "Notification Toast setting successfully set"
            Write-Host "Position $($Position)"
            Write-Host -ForegroundColor Yellow "Sign out and back in to reload settings, or restart explorer.exe"
        }
    } else {
        # IF Regkey exists:
        if (!((Get-ItemProperty -Path $regPath -Name $regName -ea 0).$($regName) -eq $regValue)) {
            # AND does NOT match value provided
            # Set value provided
            Set-ItemProperty -Path $regPath -Name $regName -Value $regValue
            if ((Get-ItemProperty -Path $regPath -Name $regName -ea 0).$($regName) -eq $regValue) {
                # Validate, Output
                Write-Host -ForegroundColor Green "Notification Toast setting successfully set"
                Write-Host "Position $($Position)"
                Write-Host -ForegroundColor Yellow "Sign out and back in to reload settings, or restart explorer.exe"
            }
        } else {
            # And does match value provided.
            # Do nothing
            Write-Host -ForegroundColor Green "Notification Toast position: $($Position)"
        }
    }

} ## END Set-Win10ToastLocation

# Set-Win10ToastLocation -Position Top
# Set-Win10ToastLocation -Position Bottom
