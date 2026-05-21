# ================================
# Red Team Recon Script (Safe)
# Author: Rajeev
# Purpose: Basic host reconnaissance
# ================================

Write-Output "=== SYSTEM INFORMATIONS ==="
Get-ComputerInfo | Select-Object OsName, OsVersion, CsName

Write-Output "`n=== CURRENT USER ==="
whoami

Write-Output "`n=== LOCAL USERS ==="
Get-LocalUser | Select-Object Name, Enabled


@nsdjf