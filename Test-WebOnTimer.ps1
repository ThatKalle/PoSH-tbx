function Test-WebOnTimer {
    param(
        [String]$Uri
    )

    $timeout = New-Timespan -Minutes 5
    $sw = [diagnostics.stopwatch]::StartNew()
    $successcount = 0
    $failurecount = 0
    While ($sw.elapsed -lt $timeout) {
        try {
            if ((Invoke-WebRequest -Uri $Uri).StatusCode -eq 200) {
                $successcount = ($($successcount) +1)
            } else {
                $failurecount = ($($failurecount) +1)
            }
        } catch {}

        Start-Sleep -Seconds 5
    }
    Write-Host -ForegroundColor Green "Job complete"
    Write-Host "Success: $($successcount)"
    if ($failurecount -gt 0) {
        Write-Host -ForegroundColor Red "Failure: $($failurecount)"
        } else {
        Write-Host "Failure: $($failurecount)"
    }
} ## END Test-WebOnTimer

#Test-WebOnTimer -Uri https://en.wikipedia.org/wiki/Special:Random
