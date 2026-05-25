$rawLogs = Get-Content "raw_auth.log"
$normalizedLogs = @()

foreach ($line in $rawLogs) {

    # Pattern 1: Failed password for user from IP
    if ($line -match "Failed password for (\w+) from ([\d\.]+)") {
        $normalizedLogs += [PSCustomObject]@{
            event_type = "authentication_failure"
            username   = $matches[1]
            src_ip     = $matches[2]
            log_source = "linux_ssh"
        }
    }

    # Pattern 2: User login failed IP=x.x.x.x
    elseif ($line -match "User (\w+) login failed IP=([\d\.]+)") {
        $normalizedLogs += [PSCustomObject]@{
            event_type = "authentication_failure"
            username   = $matches[1]
            src_ip     = $matches[2]
            log_source = "linux_ssh"
        }
    }
}

Write-Output "`n=== NORMALIZED LOGS ==="
$normalizedLogs | Format-Table -AutoSize