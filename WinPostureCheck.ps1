<#
WinPostureCheck.ps1 (v2 - hardened)
Read-only Windows 10/11 security posture assessment for everyone
- Vendor-agnostic AV detection (ESET/Defender/etc.) via Security Center (CIM + WMI fallback)
- CIS-style checks (locally verifiable)
- Browser checks (policy keys)
- Weighted scoring 0–100 (weights total exactly 100)
- Outputs: JSON + HTML + SHA256SUMS.txt
SAFE: Read-only. Only reads system state and writes report files.

Run:
  powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\WinPostureCheck.ps1 -OutDir .\report -OpenHtml
#>

[CmdletBinding()]
param(
  [string]$OutDir = ".\report",
  [switch]$OpenHtml
)

$ErrorActionPreference = "Stop"

# ---------------- Utilities ----------------
function Try-Get([scriptblock]$b) { try { & $b } catch { $null } }

function HtmlEncode([string]$s) {
  if ($null -eq $s) { return "" }
  ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;')
}

function Get-RegDwordOrNull([string]$Path, [string]$Name) {
  $v = Try-Get { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
  if ($null -eq $v) { return $null }
  try { [int]$v } catch { $null }
}

function Get-RegStringOrNull([string]$Path, [string]$Name) {
  $v = Try-Get { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
  if ($null -eq $v) { return $null }
  try { [string]$v } catch { $null }
}

function New-Finding {
  param(
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][ValidateSet("Low","Medium","High","Info")][string]$Severity,
    [Parameter(Mandatory)][ValidateSet("Pass","Fail","Unknown")][string]$Status,
    [Parameter(Mandatory)][int]$Weight,
    [string]$Evidence = "",
    [string]$Recommendation = ""
  )
  $points = if ($Status -eq "Pass") { $Weight } else { 0 }
  [pscustomobject]@{
    id = $Id
    title = $Title
    severity = $Severity
    status = $Status
    weight = $Weight
    pointsEarned = $points
    evidence = $Evidence
    recommendation = $Recommendation
  }
}

function Is-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Hardened AV discovery: CIM first, then WMI fallback, never throws
function Get-InstalledAntivirusNames {
  $names = New-Object 'System.Collections.Generic.List[string]'

  # 1) CIM (preferred)
  try {
    $cim = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
    foreach ($x in @($cim)) {
      if ($null -ne $x -and $null -ne $x.displayName -and ([string]$x.displayName).Trim().Length -gt 0) {
        $names.Add(([string]$x.displayName).Trim()) | Out-Null
      }
    }
  } catch {
    # ignore
  }

  # 2) WMI fallback (older compatibility)
  if ($names.Count -eq 0) {
    try {
      $wmi = Get-WmiObject -Namespace "root/SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction Stop
      foreach ($x in @($wmi)) {
        if ($null -ne $x -and $null -ne $x.displayName -and ([string]$x.displayName).Trim().Length -gt 0) {
          $names.Add(([string]$x.displayName).Trim()) | Out-Null
        }
      }
    } catch {
      # ignore
    }
  }

  # de-dup
  $uniq = @($names | Select-Object -Unique)
  return $uniq
}

# ---------------- Host info ----------------
$os = Get-CimInstance Win32_OperatingSystem
$hostInfo = [pscustomobject]@{
  computerName = $env:COMPUTERNAME
  userName     = "$env:USERDOMAIN\$env:USERNAME"
  os           = $os.Caption
  osVersion    = $os.Version
  isAdmin      = (Is-Admin)
}

$findings = @()

# ---------------- Data sources (read-only) ----------------
$fwProfiles   = Try-Get { Get-NetFirewallProfile }
$blVolumes    = Try-Get { Get-BitLockerVolume }
$smb1Feature  = Try-Get { Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" }
$wuaService   = Try-Get { Get-Service -Name wuauserv }
$latestHotfix = Try-Get { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
$rrService    = Try-Get { Get-Service -Name RemoteRegistry }
$defStatus    = Try-Get { Get-MpComputerStatus }  # evidence only; not required for Pass

# ---------------- Controls (Weights total = 100) ----------------

# 1) Antivirus present (vendor-agnostic) (15)
$avNames = Get-InstalledAntivirusNames
if ($avNames -and $avNames.Count -gt 0) {
  $findings += New-Finding -Id "AV-001" -Title "Antivirus protection present (Windows Security Center)" -Severity "High" `
    -Status "Pass" -Weight 15 -Evidence ("Detected AV: " + ($avNames -join ", ")) -Recommendation "None"
} else {
  $e = if ($defStatus) { "No AV names from Security Center. Defender evidence: AntivirusEnabled=$($defStatus.AntivirusEnabled); RealTime=$($defStatus.RealTimeProtectionEnabled)" } else { "No AV names from Security Center; Defender evidence unavailable." }
  $findings += New-Finding -Id "AV-001" -Title "Antivirus protection present (Windows Security Center)" -Severity "High" `
    -Status "Unknown" -Weight 15 -Evidence $e -Recommendation "Verify Defender or third-party AV is installed and enabled."
}

# 2) Firewall enabled on all profiles (12)
if ($fwProfiles) {
  $arr = @($fwProfiles)
  $disabledCount = ($arr | Where-Object { $_.Enabled -ne $true } | Measure-Object).Count
  $pass = ($disabledCount -eq 0)
  $ev = ($arr | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join "; "
  $findings += New-Finding -Id "FW-001" -Title "Windows Firewall enabled (Domain/Private/Public)" -Severity "High" `
    -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 12 -Evidence $ev `
    -Recommendation "Enable Windows Firewall on all profiles (especially Public)."
} else {
  $findings += New-Finding -Id "FW-001" -Title "Windows Firewall enabled (Domain/Private/Public)" -Severity "High" `
    -Status "Unknown" -Weight 12 -Evidence "Get-NetFirewallProfile unavailable." `
    -Recommendation "Verify firewall is enabled."
}

# 3) Disk encryption on OS volume (12)
if ($blVolumes) {
  $osVol = @($blVolumes) | Where-Object { $_.VolumeType -eq "OperatingSystem" } | Select-Object -First 1
  if ($osVol) {
    $pass = ($osVol.ProtectionStatus -eq 1)
    $findings += New-Finding -Id "ENC-001" -Title "OS disk encryption enabled (BitLocker/Device Encryption)" -Severity "High" `
      -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 12 `
      -Evidence "MountPoint=$($osVol.MountPoint); ProtectionStatus=$($osVol.ProtectionStatus); VolumeStatus=$($osVol.VolumeStatus)" `
      -Recommendation "Enable BitLocker/Device Encryption for the OS drive."
  } else {
    $findings += New-Finding -Id "ENC-001" -Title "OS disk encryption enabled (BitLocker/Device Encryption)" -Severity "High" `
      -Status "Unknown" -Weight 12 -Evidence "No OperatingSystem volume found via Get-BitLockerVolume." `
      -Recommendation "Verify BitLocker/Device Encryption availability and status."
  }
} else {
  $findings += New-Finding -Id "ENC-001" -Title "OS disk encryption enabled (BitLocker/Device Encryption)" -Severity "High" `
    -Status "Unknown" -Weight 12 -Evidence "Get-BitLockerVolume unavailable (edition/permissions may limit)." `
    -Recommendation "If supported, enable BitLocker/Device Encryption."
}

# 4) SMBv1 disabled (10)
if ($smb1Feature) {
  $pass = ($smb1Feature.State -eq "Disabled")
  $findings += New-Finding -Id "SMB-001" -Title "SMBv1 disabled" -Severity "High" `
    -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 10 -Evidence "SMB1Protocol State=$($smb1Feature.State)" `
    -Recommendation "Disable SMBv1 (legacy protocol) to reduce risk."
} else {
  $findings += New-Finding -Id "SMB-001" -Title "SMBv1 disabled" -Severity "High" `
    -Status "Unknown" -Weight 10 -Evidence "Could not query SMB1Protocol feature state." `
    -Recommendation "Ensure SMBv1 is disabled."
}

# 5) UAC enabled (8)
$uac = Get-RegDwordOrNull "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
if ($null -ne $uac) {
  $findings += New-Finding -Id "UAC-001" -Title "User Account Control (UAC) enabled" -Severity "Medium" `
    -Status ($(if ($uac -eq 1) {"Pass"} else {"Fail"})) -Weight 8 -Evidence "EnableLUA=$uac" `
    -Recommendation "Enable UAC to reduce privilege escalation risk."
} else {
  $findings += New-Finding -Id "UAC-001" -Title "User Account Control (UAC) enabled" -Severity "Medium" `
    -Status "Unknown" -Weight 8 -Evidence "EnableLUA unreadable." `
    -Recommendation "Verify UAC is enabled."
}

# 6) RDP disabled (8)
$rdp = Get-RegDwordOrNull "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
if ($null -ne $rdp) {
  $rdpEnabled = ($rdp -eq 0)
  $findings += New-Finding -Id "RDP-001" -Title "Remote Desktop disabled (or tightly controlled)" -Severity "High" `
    -Status ($(if (-not $rdpEnabled) {"Pass"} else {"Fail"})) -Weight 8 `
    -Evidence "fDenyTSConnections=$rdp (RDP enabled=$rdpEnabled)" `
    -Recommendation "Disable RDP if unused; otherwise restrict access (VPN/allow-list) and require MFA."
} else {
  $findings += New-Finding -Id "RDP-001" -Title "Remote Desktop disabled (or tightly controlled)" -Severity "High" `
    -Status "Unknown" -Weight 8 -Evidence "RDP registry value unreadable." `
    -Recommendation "Verify RDP exposure."
}

# 7) Windows Update service + recent hotfix (12)
$wuaRunning = ($wuaService -and $wuaService.Status -eq "Running")
$hasHotfix  = ($latestHotfix -ne $null)
$passWU = $wuaRunning -and $hasHotfix
$hfText = if ($latestHotfix) { "$($latestHotfix.HotFixID) installed $($latestHotfix.InstalledOn)" } else { "No hotfix data" }
$wuText = if ($wuaService) { "wuauserv=$($wuaService.Status)" } else { "wuauserv=Unknown" }
$findings += New-Finding -Id "WU-001" -Title "Windows Updates enabled + hotfix present" -Severity "High" `
  -Status ($(if ($passWU) {"Pass"} else {"Fail"})) -Weight 12 `
  -Evidence "$wuText; latestHotfix=$hfText" `
  -Recommendation "Enable Windows Update and keep devices patched (reboot when required)."

# 8) Remote Registry service not running (6)
if ($rrService) {
  $pass = ($rrService.Status -ne "Running")
  $findings += New-Finding -Id "SVC-001" -Title "Remote Registry service not running" -Severity "High" `
    -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 6 `
    -Evidence "RemoteRegistry Status=$($rrService.Status); StartType=$($rrService.StartType)" `
    -Recommendation "Disable Remote Registry unless explicitly needed."
} else {
  $findings += New-Finding -Id "SVC-001" -Title "Remote Registry service not running" -Severity "High" `
    -Status "Unknown" -Weight 6 -Evidence "RemoteRegistry service query failed." `
    -Recommendation "Verify Remote Registry is disabled/not running."
}

# 9) LSA protection (RunAsPPL) (6)
$lsa = Get-RegDwordOrNull "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
if ($null -ne $lsa) {
  $findings += New-Finding -Id "LSA-001" -Title "LSA protection enabled (RunAsPPL)" -Severity "High" `
    -Status ($(if ($lsa -ge 1) {"Pass"} else {"Fail"})) -Weight 6 `
    -Evidence "RunAsPPL=$lsa" `
    -Recommendation "Enable LSA protection to harden credential theft resistance."
} else {
  $findings += New-Finding -Id "LSA-001" -Title "LSA protection enabled (RunAsPPL)" -Severity "High" `
    -Status "Unknown" -Weight 6 -Evidence "RunAsPPL unreadable." `
    -Recommendation "Verify LSA protection setting."
}

# 10) Browser: Edge SmartScreen policy (5)
$edgeSS = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "SmartScreenEnabled"
if ($null -ne $edgeSS) {
  $findings += New-Finding -Id "BROW-EDGE-001" -Title "Edge SmartScreen enabled (policy)" -Severity "Medium" `
    -Status ($(if ($edgeSS -eq 1) {"Pass"} else {"Fail"})) -Weight 5 `
    -Evidence "SmartScreenEnabled=$edgeSS" `
    -Recommendation "Enable SmartScreen in Edge to reduce phishing/malware risk."
} else {
  $findings += New-Finding -Id "BROW-EDGE-001" -Title "Edge SmartScreen enabled (policy)" -Severity "Medium" `
    -Status "Unknown" -Weight 5 -Evidence "Edge policy key not found (may be unmanaged)." `
    -Recommendation "Verify Edge SmartScreen is enabled in browser settings."
}

# 11) Browser: Chrome Safe Browsing policy (4)
$chSB = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Google\Chrome" "SafeBrowsingProtectionLevel"
if ($null -ne $chSB) {
  $pass = ($chSB -ge 1)
  $findings += New-Finding -Id "BROW-CHR-001" -Title "Chrome Safe Browsing enabled (policy)" -Severity "Medium" `
    -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 4 `
    -Evidence "SafeBrowsingProtectionLevel=$chSB" `
    -Recommendation "Enable Safe Browsing (Standard/Enhanced)."
} else {
  $findings += New-Finding -Id "BROW-CHR-001" -Title "Chrome Safe Browsing enabled (policy)" -Severity "Medium" `
    -Status "Unknown" -Weight 4 -Evidence "Chrome policy key not found (may be unmanaged)." `
    -Recommendation "Verify Safe Browsing is enabled in Chrome settings."
}

# 12) Windows SmartScreen policy (2)
$ssEnable = Get-RegDwordOrNull "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
$ssLevel  = Get-RegStringOrNull "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"
if ($null -ne $ssEnable -or $null -ne $ssLevel) {
  $pass = ($ssEnable -eq 1) -or ($ssLevel -in @("Warn","Block"))
  $findings += New-Finding -Id "APP-001" -Title "Windows SmartScreen enabled (policy)" -Severity "Medium" `
    -Status ($(if ($pass) {"Pass"} else {"Fail"})) -Weight 2 `
    -Evidence "EnableSmartScreen=$ssEnable; ShellSmartScreenLevel=$ssLevel" `
    -Recommendation "Enable SmartScreen (Warn/Block) to reduce risky downloads/executables."
} else {
  $findings += New-Finding -Id "APP-001" -Title "Windows SmartScreen enabled (policy)" -Severity "Medium" `
    -Status "Unknown" -Weight 2 -Evidence "No SmartScreen policy keys found (may be unmanaged)." `
    -Recommendation "Verify SmartScreen is enabled in Windows Security."
}

# ---------------- Score ----------------
$total  = ($findings | Measure-Object -Property weight -Sum).Sum  # should be 100
$earned = ($findings | Measure-Object -Property pointsEarned -Sum).Sum
$score  = if ($total -gt 0) { [int][Math]::Round(100.0 * $earned / $total) } else { 0 }

# ---------------- Output ----------------
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$jsonPath = Join-Path $OutDir "win-posture-report.json"
$htmlPath = Join-Path $OutDir "win-posture-report.html"
$hashPath = Join-Path $OutDir "SHA256SUMS.txt"

$report = [pscustomobject]@{
  generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  score = $score
  scoreDetail = [pscustomobject]@{
    earnedPoints = $earned
    totalPoints  = $total
    passCount    = (@($findings) | Where-Object status -eq "Pass" | Measure-Object).Count
    failCount    = (@($findings) | Where-Object status -eq "Fail" | Measure-Object).Count
    unknownCount = (@($findings) | Where-Object status -eq "Unknown" | Measure-Object).Count
    note         = "Pass earns full weight; Fail/Unknown earn 0. Unknown often means unmanaged setting or limited permissions."
  }
  host = $hostInfo
  findings = $findings
}

$report | ConvertTo-Json -Depth 12 | Out-File -FilePath $jsonPath -Encoding utf8

# HTML table rows
$rows = ""
foreach ($x in @($findings)) {
  $cls = switch ($x.status) { "Pass" {"pass"} "Fail" {"fail"} default {"unk"} }
  $rows += "<tr class='$cls'>" +
           "<td>$(HtmlEncode $x.id)</td>" +
           "<td><b>$(HtmlEncode $x.title)</b><br/><span class='meta'>Severity: $(HtmlEncode $x.severity) | Weight: $($x.weight)</span></td>" +
           "<td>$(HtmlEncode $x.status)</td>" +
           "<td>$(HtmlEncode $x.evidence)</td>" +
           "<td>$(HtmlEncode $x.recommendation)</td>" +
           "</tr>`n"
}

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Windows Security Posture Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
  .card { border:1px solid #ddd; border-radius: 12px; padding: 12px; margin-bottom: 12px; background:#fafafa; }
  .score { font-size: 34px; font-weight: 800; margin: 6px 0 0 0; }
  .meta { color:#555; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { border-bottom: 1px solid #eee; padding: 10px; vertical-align: top; }
  th { text-align: left; background: #f3f3f3; }
  .pass td:nth-child(3) { font-weight:700; color:#0b6e0b; }
  .fail td:nth-child(3) { font-weight:700; color:#b00020; }
  .unk  td:nth-child(3) { font-weight:700; color:#7a5a00; }
</style>
</head>
<body>
  <h1>Windows Security Posture Report (Read-Only)</h1>

  <div class="card">
    <div><b>Device:</b> $(HtmlEncode $hostInfo.computerName)</div>
    <div><b>User:</b> $(HtmlEncode $hostInfo.userName)</div>
    <div><b>OS:</b> $(HtmlEncode "$($hostInfo.os) ($($hostInfo.osVersion))")</div>
    <div><b>Generated:</b> $(HtmlEncode $report.generatedAt)</div>
    <div><b>Admin run:</b> $(HtmlEncode "$($hostInfo.isAdmin)")</div>
    <div class="score">Score: $score / 100</div>
    <div class="meta">Weights total: $total. Pass earns full weight; Fail/Unknown earn 0.</div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th style="width:10%;">ID</th>
        <th style="width:30%;">Control</th>
        <th style="width:10%;">Status</th>
        <th style="width:25%;">Evidence</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      $rows
    </tbody>
  </table>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding utf8

# Hashes
$h1 = Get-FileHash -Path $jsonPath -Algorithm SHA256
$h2 = Get-FileHash -Path $htmlPath -Algorithm SHA256
@(
  "$($h1.Hash)  win-posture-report.json"
  "$($h2.Hash)  win-posture-report.html"
) | Out-File -FilePath $hashPath -Encoding utf8

Write-Host ""
Write-Host "READ-ONLY Windows Security Posture Report saved:" -ForegroundColor Cyan
Write-Host "  Score : $score / 100"
Write-Host "  JSON  : $jsonPath"
Write-Host "  HTML  : $htmlPath"
Write-Host "  HASHES: $hashPath"
Write-Host ""

if ($OpenHtml) { Start-Process $htmlPath | Out-Null }
