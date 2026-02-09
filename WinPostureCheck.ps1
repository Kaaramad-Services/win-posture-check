# WinPostureCheck.ps1 (Windows 10/11)
# READ-ONLY Windows security posture report with scoring + CIS-style checks + browser checks.
# - Produces evidence-based JSON + HTML reports
# - Does NOT modify system settings (no writes to registry/services/firewall/etc.)
# - Includes self-audit to block if "write/danger" cmdlets are detected in the script
#
# Run:
#   powershell -ExecutionPolicy Bypass -File .\WinPostureCheck.ps1 -OutDir .\report -OpenHtml

[CmdletBinding()]
param(
  [string]$OutDir = ".\report",
  [switch]$OpenHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- Safety: Self-audit (best-effort) ----------------
function Assert-ReadOnlySelfAudit {
  # This is a best-effort safeguard to reduce accidental inclusion of "write/dangerous" cmdlets.
  # It is not a sandbox, but it helps you keep the public script read-only.
  $scriptPath = $PSCommandPath
  if (-not $scriptPath -or -not (Test-Path $scriptPath)) { return }

  $content = Get-Content -LiteralPath $scriptPath -Raw

  # Block list: common write/modify/disrupt cmdlets
  $blocked = @(
    "Set-ItemProperty","New-ItemProperty","Remove-ItemProperty",
    "Set-Item","Remove-Item","Remove-ItemRecurse","Rename-Item","Move-Item","Copy-Item",
    "Set-Service","Start-Service","Stop-Service","Restart-Service",
    "Enable-NetFirewallRule","Disable-NetFirewallRule","New-NetFirewallRule","Remove-NetFirewallRule","Set-NetFirewallProfile",
    "Enable-BitLocker","Disable-BitLocker","Add-BitLockerKeyProtector","Remove-BitLockerKeyProtector",
    "Install-Module","Install-Package","Add-WindowsCapability","Remove-WindowsCapability",
    "Enable-WindowsOptionalFeature","Disable-WindowsOptionalFeature",
    "Invoke-WebRequest","Invoke-RestMethod", # avoid pulling arbitrary remote content
    "Start-Process","schtasks","Register-ScheduledTask",
    "reg add","reg delete","netsh","bcdedit","diskpart"
  )

  foreach ($b in $blocked) {
    if ($content -match [regex]::Escape($b)) {
      throw "SAFETY BLOCK: The script contains a blocked command token '$b'. This tool is intended to be READ-ONLY."
    }
  }
}

Assert-ReadOnlySelfAudit

# ---------------- Utilities ----------------
function Is-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Try-Get([scriptblock]$Block) { try { & $Block } catch { $null } }

function Get-RegistryValue([string]$Path, [string]$Name) {
  Try-Get { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
}

function Get-RegDwordOrNull([string]$Path, [string]$Name) {
  $v = Get-RegistryValue $Path $Name
  if ($null -eq $v) { return $null }
  try { return [int]$v } catch { return $null }
}

function HtmlEncode([string]$s) {
  if ($null -eq $s) { return "" }
  # Minimal safe encoding for HTML output
  return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;')
}

function New-Finding {
  param(
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][ValidateSet("Low","Medium","High","Info")][string]$Severity,
    [Parameter(Mandatory)][ValidateSet("Pass","Fail","Unknown")][string]$Status,
    [string]$Evidence = "",
    [string]$Recommendation = "",
    [int]$Weight = 0,
    [int]$PointsEarned = 0
  )
  [pscustomobject]@{
    id = $Id
    title = $Title
    severity = $Severity
    status = $Status
    weight = $Weight
    pointsEarned = $PointsEarned
    evidence = $Evidence
    recommendation = $Recommendation
  }
}

function Add-ControlResult {
  param(
    [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Findings,
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][ValidateSet("Low","Medium","High","Info")][string]$Severity,
    [Parameter(Mandatory)][int]$Weight,
    [Parameter(Mandatory)][ValidateSet("Pass","Fail","Unknown")][string]$Status,
    [string]$Evidence = "",
    [string]$Recommendation = ""
  )
  $earned = if ($Status -eq "Pass") { $Weight } else { 0 }  # Fail/Unknown earn 0 (transparent)
  $Findings.Add((New-Finding -Id $Id -Title $Title -Severity $Severity -Status $Status -Evidence $Evidence -Recommendation $Recommendation -Weight $Weight -PointsEarned $earned))
}

function Write-ReportFiles {
  param([Parameter(Mandatory)]$ReportObj, [Parameter(Mandatory)][string]$OutDir)

  New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
  $jsonPath = Join-Path $OutDir "win-posture-report.json"
  $htmlPath = Join-Path $OutDir "win-posture-report.html"
  $hashPath = Join-Path $OutDir "SHA256SUMS.txt"

  $ReportObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8

  $f = $ReportObj.findings
  $score = $ReportObj.score

  $html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Windows Security Posture Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
  .meta { margin-bottom: 16px; padding: 12px; border: 1px solid #ddd; border-radius: 12px; }
  .score { font-size: 34px; font-weight: 800; margin: 6px 0 0 0; }
  .pill { display:inline-block; padding: 2px 10px; border: 1px solid #ddd; border-radius: 999px; font-size: 12px; margin: 4px 6px 0 0; }
  table { width: 100%; border-collapse: collapse; }
  th, td { border-bottom: 1px solid #eee; padding: 10px; vertical-align: top; }
  th { text-align: left; background: #fafafa; }
  .fail { color: #b00020; font-weight: 700; }
  .pass { color: #0b6e0b; font-weight: 700; }
  .unknown { color: #7a5a00; font-weight: 700; }
  .sev-High { font-weight: 800; }
  .banner { background:#f6f8fa; border:1px solid #ddd; padding:10px 12px; border-radius:12px; margin-bottom: 12px; }
  code { background:#f6f8fa; padding:2px 6px; border-radius:8px; }
</style>
</head>
<body>
  <h1>Windows Security Posture Report</h1>

  <div class="banner">
    <b>READ-ONLY TOOL</b>: This report is generated by querying system settings and writing output files only.
    It does not change system configuration. Run as Administrator for more complete results.
  </div>

  <div class="meta">
    <div class="pill"><b>Device:</b> $(HtmlEncode $ReportObj.host.computerName)</div>
    <div class="pill"><b>User:</b> $(HtmlEncode $ReportObj.host.userName)</div>
    <div class="pill"><b>OS:</b> $(HtmlEncode "$($ReportObj.host.os) ($($ReportObj.host.osVersion))")</div>
    <div class="pill"><b>Generated:</b> $(HtmlEncode $ReportObj.generatedAt)</div>
    <div class="pill"><b>Admin run:</b> $(HtmlEncode "$($ReportObj.host.isAdmin)")</div>
    <div class="score">Score: $score / 100</div>
    <div><b>Scoring note:</b> Pass earns full weight; Fail/Unknown earn 0 (Unknown usually means permissions/availability).</div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th style="width:10%;">Status</th>
        <th style="width:10%;">Severity</th>
        <th style="width:8%;">Weight</th>
        <th style="width:22%;">Control</th>
        <th>Evidence / Recommendation</th>
      </tr>
    </thead>
    <tbody>
"@

  foreach ($x in $f) {
    $statusClass = switch ($x.status) { "Fail" {"fail"} "Pass" {"pass"} default {"unknown"} }
    $html += "<tr>"
    $html += "<td class='$statusClass'>$(HtmlEncode $x.status)</td>"
    $html += "<td class='sev-$($x.severity)'>$(HtmlEncode $x.severity)</td>"
    $html += "<td>$(HtmlEncode "$($x.weight)")</td>"
    $html += "<td><b>$(HtmlEncode $x.title)</b><br/><span class='pill'>$(HtmlEncode $x.id)</span></td>"
    $html += "<td><div><b>Evidence:</b> $(HtmlEncode $x.evidence)</div>"
    if ($x.recommendation) { $html += "<div style='margin-top:6px;'><b>Recommendation:</b> $(HtmlEncode $x.recommendation)</div>" }
    $html += "</td></tr>"
  }

  $html += @"
    </tbody>
  </table>
</body>
</html>
"@

  $html | Out-File -FilePath $htmlPath -Encoding utf8

  # Hash outputs (helps users validate report integrity)
  $h1 = Get-FileHash -Path $jsonPath -Algorithm SHA256
  $h2 = Get-FileHash -Path $htmlPath -Algorithm SHA256
  @(
    "$($h1.Hash)  $(Split-Path -Leaf $jsonPath)"
    "$($h2.Hash)  $(Split-Path -Leaf $htmlPath)"
  ) | Out-File -FilePath $hashPath -Encoding utf8

  [pscustomobject]@{ json = $jsonPath; html = $htmlPath; hashes = $hashPath }
}

# ---------------- Host info ----------------
$hostInfo = [pscustomobject]@{
  computerName = $env:COMPUTERNAME
  userName     = "$env:USERDOMAIN\$env:USERNAME"
  os           = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
  osVersion    = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)
  isAdmin      = (Is-Admin)
}

$findings = New-Object 'System.Collections.Generic.List[object]'

# ---------------- Data sources (read-only queries) ----------------
$defStatus   = Try-Get { Get-MpComputerStatus }
$defPref     = Try-Get { Get-MpPreference }
$fwProfiles  = Try-Get { Get-NetFirewallProfile }
$bitlocker   = Try-Get { Get-BitLockerVolume }
$latestHotfix = Try-Get { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 }

# ---------------- Controls (weights sum to 100) ----------------
# NOTE: weights are chosen to total 100 for a clean score.

# 1) Defender active + real-time (10)
if ($defStatus) {
  $pass = ($defStatus.RealTimeProtectionEnabled -eq $true) -and ($defStatus.AntivirusEnabled -eq $true)
  Add-ControlResult $findings "CIS-AV-001" "Antivirus active + Real-time protection (Defender)" "High" 10 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "RealTimeProtectionEnabled=$($defStatus.RealTimeProtectionEnabled); AntivirusEnabled=$($defStatus.AntivirusEnabled)" `
    "Enable real-time protection and ensure a reputable AV is active."
} else {
  Add-ControlResult $findings "CIS-AV-001" "Antivirus active + Real-time protection (Defender)" "High" 10 "Unknown" `
    "Get-MpComputerStatus unavailable." "Verify AV is installed and active."
}

# 2) Defender cloud protection + sample submission (4)
if ($defPref) {
  $pass = ($defPref.MAPSReporting -ge 1) -and ($defPref.SubmitSamplesConsent -ge 1)
  Add-ControlResult $findings "CIS-AV-002" "Cloud-delivered protection + sample submission (Defender)" "Medium" 4 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "MAPSReporting=$($defPref.MAPSReporting); SubmitSamplesConsent=$($defPref.SubmitSamplesConsent)" `
    "Turn on cloud-delivered protection and sample submission."
} else {
  Add-ControlResult $findings "CIS-AV-002" "Cloud-delivered protection + sample submission (Defender)" "Medium" 4 "Unknown" `
    "Get-MpPreference unavailable." "Verify Defender preferences."
}

# 3) PUA protection (4)
if ($defPref) {
  $pass = ($defPref.PUAProtection -in 1,2) # 1=Enabled, 2=Audit
  Add-ControlResult $findings "CIS-AV-003" "Potentially Unwanted App (PUA) protection enabled/audit" "Medium" 4 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "PUAProtection=$($defPref.PUAProtection)" `
    "Enable PUA protection to reduce adware/PUA risk."
} else {
  Add-ControlResult $findings "CIS-AV-003" "Potentially Unwanted App (PUA) protection enabled/audit" "Medium" 4 "Unknown" `
    "Get-MpPreference unavailable." "Verify PUA protection."
}

# 4) Firewall all profiles enabled (10)
if ($fwProfiles) {
  $allOn = ($fwProfiles | Where-Object { $_.Enabled -ne $true } | Measure-Object).Count -eq 0
  $ev = ($fwProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join "; "
  Add-ControlResult $findings "CIS-FW-001" "Windows Firewall enabled (Domain/Private/Public)" "High" 10 `
    ($(if ($allOn) {"Pass"} else {"Fail"})) `
    $ev `
    "Enable firewall on all profiles (especially Public)."
} else {
  Add-ControlResult $findings "CIS-FW-001" "Windows Firewall enabled (Domain/Private/Public)" "High" 10 "Unknown" `
    "Get-NetFirewallProfile unavailable." "Verify firewall status."
}

# 5) BitLocker OS volume protected (12)
if ($bitlocker) {
  $osVol = $bitlocker | Where-Object { $_.VolumeType -eq "OperatingSystem" } | Select-Object -First 1
  if ($osVol) {
    $pass = ($osVol.ProtectionStatus -eq 1)
    Add-ControlResult $findings "CIS-ENC-001" "Disk encryption enabled on OS volume (BitLocker)" "High" 12 `
      ($(if ($pass) {"Pass"} else {"Fail"})) `
      "MountPoint=$($osVol.MountPoint); ProtectionStatus=$($osVol.ProtectionStatus); VolumeStatus=$($osVol.VolumeStatus)" `
      "Enable BitLocker/device encryption for the OS drive."
  } else {
    Add-ControlResult $findings "CIS-ENC-001" "Disk encryption enabled on OS volume (BitLocker)" "High" 12 "Unknown" `
      "No OS BitLocker volume found." "Verify device encryption/BitLocker availability."
  }
} else {
  Add-ControlResult $findings "CIS-ENC-001" "Disk encryption enabled on OS volume (BitLocker)" "High" 12 "Unknown" `
    "Get-BitLockerVolume unavailable (often Windows Home/non-admin)." "If supported, enable BitLocker/device encryption."
}

# 6) UAC enabled (6)
$enableLua = Get-RegDwordOrNull "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
if ($null -ne $enableLua) {
  Add-ControlResult $findings "CIS-UAC-001" "User Account Control (UAC) enabled" "Medium" 6 `
    ($(if ($enableLua -eq 1) {"Pass"} else {"Fail"})) `
    "EnableLUA=$enableLua" "Enable UAC."
} else {
  Add-ControlResult $findings "CIS-UAC-001" "User Account Control (UAC) enabled" "Medium" 6 "Unknown" `
    "EnableLUA unreadable." "Verify UAC."
}

# 7) Windows SmartScreen (policy-based check) (6)
$ssEnable = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
$ssLevel  = Try-Get { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" }
if ($null -ne $ssEnable -or $null -ne $ssLevel) {
  $pass = ($ssEnable -eq 1) -or ($ssLevel -in @("Warn","Block"))
  Add-ControlResult $findings "CIS-APP-001" "Microsoft SmartScreen enabled (policy)" "Medium" 6 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "EnableSmartScreen=$ssEnable; ShellSmartScreenLevel=$ssLevel" `
    "Enable SmartScreen (Warn/Block)."
} else {
  Add-ControlResult $findings "CIS-APP-001" "Microsoft SmartScreen enabled (policy)" "Medium" 6 "Unknown" `
    "No SmartScreen policy keys found." "Confirm SmartScreen is enabled in Windows Security/Edge."
}

# 8) RDP disabled / controlled (8)
$rdpDeny = Get-RegDwordOrNull "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
if ($null -ne $rdpDeny) {
  $rdpEnabled = ($rdpDeny -eq 0)
  Add-ControlResult $findings "CIS-RDP-001" "Remote Desktop disabled (or tightly controlled)" "High" 8 `
    ($(if (-not $rdpEnabled) {"Pass"} else {"Fail"})) `
    "fDenyTSConnections=$rdpDeny (RDP enabled=$rdpEnabled)" `
    "Disable RDP if not needed; otherwise restrict via VPN/firewall allow-list + MFA."
} else {
  Add-ControlResult $findings "CIS-RDP-001" "Remote Desktop disabled (or tightly controlled)" "High" 8 "Unknown" `
    "RDP registry value unreadable." "Verify RDP exposure."
}

# 9) SMBv1 disabled (8)
$smb1 = Try-Get { Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" }
if ($smb1) {
  Add-ControlResult $findings "CIS-SMB-001" "SMBv1 disabled" "High" 8 `
    ($(if ($smb1.State -eq "Disabled") {"Pass"} else {"Fail"})) `
    "SMB1Protocol State=$($smb1.State)" "Disable SMBv1."
} else {
  Add-ControlResult $findings "CIS-SMB-001" "SMBv1 disabled" "High" 8 "Unknown" `
    "Could not query SMB1Protocol." "Ensure SMBv1 is disabled."
}

# 10) LSA protection (RunAsPPL) (6)
$lsa = Get-RegDwordOrNull "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
if ($null -ne $lsa) {
  Add-ControlResult $findings "CIS-LSA-001" "LSA protection enabled (RunAsPPL)" "High" 6 `
    ($(if ($lsa -ge 1) {"Pass"} else {"Fail"})) `
    "RunAsPPL=$lsa" "Enable LSA protection."
} else {
  Add-ControlResult $findings "CIS-LSA-001" "LSA protection enabled (RunAsPPL)" "High" 6 "Unknown" `
    "RunAsPPL unreadable." "Verify LSA protection."
}

# 11) WDigest plaintext creds disabled (4)
$wd = Get-RegDwordOrNull "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
if ($null -eq $wd) {
  Add-ControlResult $findings "CIS-CRED-001" "WDigest plaintext credential storage disabled" "High" 4 "Pass" `
    "UseLogonCredential not set (secure default on modern Windows)." "Keep WDigest plaintext disabled."
} else {
  Add-ControlResult $findings "CIS-CRED-001" "WDigest plaintext credential storage disabled" "High" 4 `
    ($(if ($wd -eq 0) {"Pass"} else {"Fail"})) `
    "UseLogonCredential=$wd" "Set UseLogonCredential=0."
}

# 12) Windows Update running + hotfix present (6)
$wua = Try-Get { (Get-Service -Name wuauserv).Status }
$hfText = if ($latestHotfix) { "$($latestHotfix.HotFixID) installed $($latestHotfix.InstalledOn)" } else { "No hotfix data" }
$passWU = ($wua -eq "Running") -and ($latestHotfix -ne $null)
Add-ControlResult $findings "CIS-WU-001" "Windows Update enabled + recent hotfix present" "Medium" 6 `
  ($(if ($passWU) {"Pass"} else {"Fail"})) `
  "wuauserv=$wua; latestHotfix=$hfText" "Keep Windows patched."

# 13) Edge SmartScreen (policy) (5)
$edgeSS = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled"
if ($null -ne $edgeSS) {
  Add-ControlResult $findings "BROW-EDGE-001" "Microsoft Edge SmartScreen enabled (policy)" "Medium" 5 `
    ($(if ($edgeSS -eq 1) {"Pass"} else {"Fail"})) `
    "Edge SmartScreenEnabled=$edgeSS" "Enable Edge SmartScreen."
} else {
  Add-ControlResult $findings "BROW-EDGE-001" "Microsoft Edge SmartScreen enabled (policy)" "Medium" 5 "Unknown" `
    "No Edge SmartScreen policy key found." "Confirm Edge SmartScreen is enabled in Edge settings."
}

# 14) Chrome Safe Browsing (policy) (5)
$chSS = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Google\Chrome" "SafeBrowsingProtectionLevel"
if ($null -ne $chSS) {
  $pass = ($chSS -ge 1) # 1=Standard, 2=Enhanced
  Add-ControlResult $findings "BROW-CHR-001" "Google Chrome Safe Browsing enabled (policy)" "Medium" 5 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "Chrome SafeBrowsingProtectionLevel=$chSS" "Enable Safe Browsing (Standard/Enhanced)."
} else {
  Add-ControlResult $findings "BROW-CHR-001" "Google Chrome Safe Browsing enabled (policy)" "Medium" 5 "Unknown" `
    "No Chrome Safe Browsing policy key found." "Confirm Safe Browsing is enabled in Chrome settings."
}

# 15) TLS 1.0/1.1 disabled (SCHANNEL client) (6)
function Get-TlsDisabled([string]$proto) {
  $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client"
  $enabled = Get-RegDwordOrNull $base "Enabled"
  $disabledByDefault = Get-RegDwordOrNull $base "DisabledByDefault"
  if ($null -eq $enabled -and $null -eq $disabledByDefault) { return $null }
  return ($enabled -eq 0) -or ($disabledByDefault -eq 1)
}
$t10 = Get-TlsDisabled "TLS 1.0"
$t11 = Get-TlsDisabled "TLS 1.1"
if ($null -ne $t10 -or $null -ne $t11) {
  $pass = ($t10 -eq $true) -and ($t11 -eq $true)
  Add-ControlResult $findings "CIS-TLS-001" "TLS 1.0 and 1.1 disabled (SCHANNEL client)" "Medium" 6 `
    ($(if ($pass) {"Pass"} else {"Fail"})) `
    "TLS1.0Disabled=$t10; TLS1.1Disabled=$t11" "Disable TLS 1.0/1.1 where compatible."
} else {
  Add-ControlResult $findings "CIS-TLS-001" "TLS 1.0 and 1.1 disabled (SCHANNEL client)" "Medium" 6 "Unknown" `
    "SCHANNEL TLS disable keys not present." "Consider disabling TLS 1.0/1.1 if compatible."
}

# 16) Remote Registry not running (6)
$rr = Try-Get { Get-Service -Name "RemoteRegistry" }
if ($rr) {
  Add-ControlResult $findings "CIS-SVC-001" "Remote Registry service disabled/not running" "High" 6 `
    ($(if ($rr.Status -ne "Running") {"Pass"} else {"Fail"})) `
    "Status=$($rr.Status); StartType=$($rr.StartType)" "Disable Remote Registry unless required."
} else {
  Add-ControlResult $findings "CIS-SVC-001" "Remote Registry service disabled/not running" "High" 6 "Unknown" `
    "RemoteRegistry service query failed." "Verify Remote Registry is disabled."
}

# ---------------- Score ----------------
$totalWeight = ($findings | Measure-Object -Property weight -Sum).Sum
$earned      = ($findings | Measure-Object -Property pointsEarned -Sum).Sum
$unknownCnt  = ($findings | Where-Object status -eq "Unknown" | Measure-Object).Count
$failCnt     = ($findings | Where-Object status -eq "Fail" | Measure-Object).Count
$passCnt     = ($findings | Where-Object status -eq "Pass" | Measure-Object).Count
$score = if ($totalWeight -gt 0) { [int][Math]::Round(100.0 * $earned / $totalWeight) } else { 0 }

$report = [pscustomobject]@{
  generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  score       = $score
  scoreDetail = [pscustomobject]@{
    earnedPoints = $earned
    totalPoints  = $totalWeight
    passCount    = $passCnt
    failCount    = $failCnt
    unknownCount = $unknownCnt
    note         = "Pass earns full weight; Fail/Unknown earn 0. Unknown often means permissions or feature availability."
  }
  host        = $hostInfo
  findings    = $findings
}

$paths = Write-ReportFiles -ReportObj $report -OutDir $OutDir

Write-Host ""
Write-Host "READ-ONLY Windows Security Posture Report saved:" -ForegroundColor Cyan
Write-Host "  Score : $score / 100"
Write-Host "  JSON  : $($paths.json)"
Write-Host "  HTML  : $($paths.html)"
Write-Host "  HASHES: $($paths.hashes)"
Write-Host ("  Pass: {0} | Fail: {1} | Unknown: {2}" -f $passCnt, $failCnt, $unknownCnt)
Write-Host ""

if ($OpenHtml) { & explorer.exe $paths.html | Out-Null }
