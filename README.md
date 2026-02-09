# Windows Security Posture Check (Read-Only)

A **read-only Windows 10/11 security posture assessment tool** that evaluates local system security against practical **CIS-style controls**, detects **any installed antivirus (Defender, Kespersky, etc.)**, and produces **evidence-based reports** with a **0–100 weighted security score**.

This project is designed for:

- Cybersecurity learning & portfolio demonstration  
- Endpoint posture validation  
- Defensive security awareness  
- Safe execution in enterprise environments  

---

## Key Features

### Vendor-agnostic antivirus detection
Works with **Microsoft Defender, McAfee, and other AV products** via Windows Security Center.

### CIS-style local security checks

- Firewall status  
- Disk encryption (BitLocker / Device Encryption)  
- SMBv1 disabled  
- UAC enabled  
- RDP exposure  
- Windows Update status  
- Remote Registry service  
- LSA protection  

### Browser security validation

- Microsoft Edge SmartScreen policy  
- Google Chrome Safe Browsing policy  
- Windows SmartScreen configuration  

### Weighted 0–100 security scoring

- Evidence-based scoring  
- Pass / Fail / Unknown classification  
- Transparent control weights  

### Professional reporting

- JSON report *(machine-readable)*  
- HTML dashboard *(human-readable)*  
- SHA-256 integrity hashes  

### Fully read-only & safe

- No system configuration changes  
- No network calls  
- Suitable for enterprise testing  

---

## Requirements

- **Windows 10 or 11**  
- **PowerShell 5.1 or later**  
- **Administrator privileges recommended** for full visibility  
  *(script still runs without admin, but some checks may show `Unknown`)*  

---

## Usage
### Run locally

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\WinPostureCheck.ps1 -OutDir .\report -OpenHtml
