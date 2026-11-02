# TwinDesk - Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
# Replace one marked key, or remove every app-owned marker. Report actual completion to the caller.
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [Parameter(Mandatory = $true)][string]$Marker,
  [Parameter(Mandatory = $true)][string]$Result,
  [ValidateSet('yes', 'no')][string]$All = 'no',
  [string]$LegacyMarker = '',
  [string]$KeyFile = ''
)
$ErrorActionPreference = 'Stop'
try {
  $keep = @()
  if (Test-Path $Path) {
    $keep = @(Get-Content $Path | Where-Object {
      if ($All -eq 'yes') { $_ -notmatch ' macshare:[^\s]+$' }
      else { -not $_.EndsWith($Marker) -and (-not $LegacyMarker -or -not $_.EndsWith($LegacyMarker)) }
    })
  }
  if ($KeyFile) { $keep += (Get-Content -Raw $KeyFile).Trim() }
  if ((Test-Path $Path) -or $KeyFile) { Set-Content -Path $Path -Value $keep -Encoding ascii }
  if ($KeyFile) {
    icacls $Path /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the SSH key file' }
  }
  Set-Content -Path $Result -Value 'ok'
} catch { Set-Content -Path $Result -Value ('error: ' + $_.Exception.Message) }
