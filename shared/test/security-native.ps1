# Regression checks for the elevated scripts. All account/share commands are mocked;
# real filesystem changes are confined to this test's fresh temporary directory.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$fixtureDir = Join-Path ([IO.Path]::GetTempPath()) ('duodesk-native-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $fixtureDir | Out-Null
function Assert($condition, $message) { if (-not $condition) { throw $message } }
try {
  $keys = Join-Path $fixtureDir 'authorized_keys'
  $result = Join-Path $fixtureDir 'result.txt'
  $keyFile = Join-Path $fixtureDir 'new-key.txt'
  function icacls { $global:LASTEXITCODE = 0 }
  Set-Content $keys @('ssh-ed25519 MANUAL personal', 'ssh-ed25519 AAAA macshare:a', 'ssh-ed25519 BBBB macshare:b')
  & (Join-Path $repoRoot 'windows/scripts/sshd-key.ps1') -Path $keys -Marker ' macshare:b' -Result $result
  Assert ((Get-Content $result -Raw).Trim() -eq 'ok') 'key removal failed'
  Assert ((Get-Content $keys).Count -eq 2) 'exact key deletion affected another key'
  Set-Content $keyFile 'ssh-ed25519 CCCC macshare:a'
  & (Join-Path $repoRoot 'windows/scripts/sshd-key.ps1') -Path $keys -Marker ' macshare:a' -KeyFile $keyFile -Result $result
  Assert ((Get-Content $keys -Raw) -match 'CCCC macshare:a') 'ordinary install failed'
  & (Join-Path $repoRoot 'windows/scripts/sshd-key.ps1') -Path $keys -Marker ' macshare:' -All yes -Result $result
  Assert ((Get-Content $keys -Raw).Trim() -eq 'ssh-ed25519 MANUAL personal') 'global Off did not preserve manual keys'
  $missing = Join-Path $fixtureDir 'missing/keys'
  & (Join-Path $repoRoot 'windows/scripts/sshd-key.ps1') -Path $missing -Marker ' macshare:a' -KeyFile $keyFile -Result $result
  Assert ((Get-Content $result -Raw).StartsWith('error:')) 'key write failure reported success'
  Write-Output 'PASS elevated SSH script: exact/global removal, ordinary install, error result'

  $nativeState = @{ shares = @('MacShare', 'Unrelated'); users = @('macshare', 'Unrelated'); deny = $false }
  function Get-SmbShare { $nativeState.shares | ForEach-Object { [pscustomobject]@{Name=$_} } }
  function Get-LocalUser { $nativeState.users | ForEach-Object { [pscustomobject]@{Name=$_} } }
  function Remove-SmbShare { param($Name, [switch]$Force); if ($nativeState.deny) { throw 'denied' }; $nativeState.shares = @($nativeState.shares | Where-Object { $_ -ne $Name }) }
  function Remove-LocalUser { param($Name); $nativeState.users = @($nativeState.users | Where-Object { $_ -ne $Name }) }
  # This test does not read or write the registry.
  function Test-Path { param($Path); if ([string]$Path -like 'HKLM:*') { return $false }; Microsoft.PowerShell.Management\Test-Path $Path }
  $nativeState.deny = $true
  & (Join-Path $repoRoot 'windows/scripts/smb-unshare.ps1') -Share MacShare -User macshare -Result $result
  Assert ((Get-Content $result -Raw).StartsWith('error:')) 'share failure reported success'
  Assert ($nativeState.users -contains 'macshare') 'failure removed recovery account'
  $nativeState.deny = $false
  & (Join-Path $repoRoot 'windows/scripts/smb-unshare.ps1') -Share MacShare -User macshare -Result $result
  Assert ((Get-Content $result -Raw).Trim() -eq 'ok') 'share cleanup failed'
  Assert (($nativeState.shares -join ',') -eq 'Unrelated') 'cleanup touched unrelated share'
  Assert (($nativeState.users -join ',') -eq 'Unrelated') 'cleanup touched unrelated user'
  & (Join-Path $repoRoot 'windows/scripts/smb-unshare.ps1') -Share MacShare -User macshare -Result $result
  Assert ((Get-Content $result -Raw).Trim() -eq 'ok') 'repeated cleanup failed'
  Write-Output 'PASS elevated SMB script: failure, scoped cleanup, idempotent retry'
} finally {
  $resolved = [IO.Path]::GetFullPath($fixtureDir)
  $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notlike 'duodesk-native-*') { throw 'Unexpected fixture directory' }
  Remove-Item -LiteralPath $resolved -Recurse -Force
}
