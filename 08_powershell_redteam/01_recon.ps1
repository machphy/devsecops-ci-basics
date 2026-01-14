# ================================
# Red Team Recon Script (Safe)
# Author: Rajeev
# Purpose: Basic host reconnaissance
# ================================

Write-Output "=== SYSTEM INFORMATION ==="
Get-ComputerInfo | Select-Object OsName, OsVersion, CsName

Write-Output "`n=== CURRENT USER ==="
whoami

Write-Output "`n=== LOCAL USERS ==="
Get-LocalUser | Select-Object Name, Enabled

Write-Output "`n=== NETWORK INFORMATION ==="
Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias

