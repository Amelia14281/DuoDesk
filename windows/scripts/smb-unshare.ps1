# TwinDesk - Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
# Remove only the app's share/account. Removing the share also disconnects its existing clients.
param(
  [Parameter(Mandatory = $true)][string]$Share,
  [Parameter(Mandatory = $true)][string]$User,
  [Parameter(Mandatory = $true)][string]$Result
)
$ErrorActionPreference = 'Stop'
try {
  # Enumerate rather than swallowing lookup errors (a stopped server is not proof of absence).
  if (Get-SmbShare | Where-Object Name -eq $Share) { Remove-SmbShare -Name $Share -Force }
  if (Get-LocalUser | Where-Object Name -eq $User) { Remove-LocalUser -Name $User }
  if (Get-SmbShare | Where-Object Name -eq $Share) { throw 'The share still exists' }
  if (Get-LocalUser | Where-Object Name -eq $User) { throw 'The sharing account still exists' }
  $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
  if ((Test-Path $key) -and (Get-Item $key).GetValueNames().Contains($User)) {
    Remove-ItemProperty -Path $key -Name $User
  }
  Set-Content -Path $Result -Value 'ok'
} catch { Set-Content -Path $Result -Value ('error: ' + $_.Exception.Message) }
